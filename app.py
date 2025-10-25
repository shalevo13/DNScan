#!/usr/bin/env python3
"""
DNS Vulnerability Scanner - Web Application
Flask backend for DNS security testing
"""

from flask import Flask, render_template, request, jsonify
import dns.resolver, dns.query, dns.zone, dns.exception, dns.name
import random
from datetime import datetime

app = Flask(__name__)

class DNSScanner:
    def __init__(self, domain, nameserver):
        self.domain = domain
        self.nameserver = nameserver
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.timeout = 3.0
        self.resolver.lifetime = 6.0
        self.resolver.nameservers = [nameserver]
        self.results = {
            'domain': domain,
            'nameserver': nameserver,
            'timestamp': datetime.now().isoformat(),
            'tests': []
        }
    
    def get_ns(self):
        try:
            ans = self.resolver.resolve(self.domain, 'NS')
            return [str(r.target).rstrip('.') for r in ans]
        except Exception as e:
            return []
    
    def check_axfr(self):
        test = {
            'name': 'Zone Transfer (AXFR)',
            'description': 'Checks if zone transfers are allowed',
            'status': 'safe',
            'severity': 'critical',
            'details': []
        }
        
        discovered = []
        ns = self.get_ns()
        
        if not ns:
            test['status'] = 'error'
            test['details'].append('Could not resolve nameservers')
            return test
        
        for n in ns:
            try:
                xfr = dns.query.xfr(self.nameserver, self.domain, timeout=5)
                z = dns.zone.from_xfr(xfr)
                if z:
                    nodes = list(z.nodes)
                    test['status'] = 'vulnerable'
                    test['details'].append(f'AXFR allowed on {n}! Retrieved {len(nodes)} records')
                    discovered.append((n, len(nodes)))
            except Exception:
                pass
        
        if not discovered:
            test['details'].append('Zone transfers properly restricted')
        
        return test
    
    def check_spf_dmarc(self):
        spf_test = {
            'name': 'SPF Record',
            'description': 'Sender Policy Framework configuration',
            'status': 'missing',
            'severity': 'medium',
            'details': []
        }
        
        dmarc_test = {
            'name': 'DMARC Record',
            'description': 'Domain-based Message Authentication',
            'status': 'missing',
            'severity': 'medium',
            'details': []
        }
        
        # Check SPF
        try:
            for r in self.resolver.resolve(self.domain, 'TXT'):
                txt = b"".join(r.strings).decode(errors='ignore')
                if "v=spf1" in txt.lower():
                    spf_test['status'] = 'safe'
                    spf_test['details'].append(f'SPF record found: {txt}')
                    break
        except Exception as e:
            spf_test['details'].append('No SPF record found')
        
        if not spf_test['details']:
            spf_test['details'].append('No SPF record configured')
        
        # Check DMARC
        try:
            for r in self.resolver.resolve("_dmarc." + self.domain, 'TXT'):
                txt = b"".join(r.strings).decode(errors='ignore')
                if "v=dmarc1" in txt.lower():
                    dmarc_test['status'] = 'safe'
                    dmarc_test['details'].append(f'DMARC record found: {txt}')
                    break
        except Exception as e:
            dmarc_test['details'].append('No DMARC record found')
        
        if not dmarc_test['details']:
            dmarc_test['details'].append('No DMARC record configured')
        
        return [spf_test, dmarc_test]
    
    def check_wildcard(self):
        test = {
            'name': 'Wildcard DNS',
            'description': 'Checks for wildcard DNS records',
            'status': 'safe',
            'severity': 'low',
            'details': []
        }
        
        rnd = str(random.randint(100000, 999999))
        test_domain = f"{rnd}.test.{self.domain}"
        
        try:
            self.resolver.resolve(test_domain, 'A')
            test['status'] = 'warning'
            test['details'].append(f'Wildcard detected: {test_domain} resolved')
        except dns.resolver.NXDOMAIN:
            test['details'].append('No wildcard DNS detected')
        except Exception:
            test['details'].append('No wildcard detected or query blocked')
        
        return test
    
    def check_mx(self):
        test = {
            'name': 'MX Records',
            'description': 'Mail exchanger configuration',
            'status': 'safe',
            'severity': 'medium',
            'details': []
        }
        
        try:
            mxs = self.resolver.resolve(self.domain, 'MX')
            problems = []
            
            for m in mxs:
                exchange = str(m.exchange).rstrip('.')
                test['details'].append(f'MX: {exchange} (priority {m.preference})')
                try:
                    self.resolver.resolve(exchange, 'A')
                except Exception:
                    problems.append(exchange)
            
            if problems:
                test['status'] = 'vulnerable'
                test['details'].append(f'Warning: MX points to non-resolving hosts: {", ".join(problems)}')
        except Exception:
            test['status'] = 'warning'
            test['details'].append('No MX records found')
        
        return test
    
    def check_cname_takeover(self):
        test = {
            'name': 'CNAME Takeover Risk',
            'description': 'Potential subdomain takeover vulnerabilities',
            'status': 'safe',
            'severity': 'high',
            'details': []
        }
        
        candidates = ["oldservice." + self.domain, "dev." + self.domain, 
                     "staging." + self.domain, "test." + self.domain]
        issues = []
        
        for c in candidates:
            try:
                ans = self.resolver.resolve(c, 'CNAME')
                target = str(ans[0].target).rstrip('.')
                if "." in target and not target.endswith(self.domain):
                    issues.append((c, target))
            except Exception:
                pass
        
        if issues:
            test['status'] = 'warning'
            for subdomain, target in issues:
                test['details'].append(f'{subdomain} -> {target} (external CNAME)')
        else:
            test['details'].append('No obvious risky CNAMEs found')
        
        return test
    
    def check_ns_health(self):
        test = {
            'name': 'Nameserver Health',
            'description': 'Nameserver availability and configuration',
            'status': 'safe',
            'severity': 'high',
            'details': []
        }
        
        ns = self.get_ns()
        
        if not ns:
            test['status'] = 'vulnerable'
            test['details'].append('No nameservers found')
            return test
        
        for n in ns:
            try:
                a = self.resolver.resolve(n, 'A')
                test['details'].append(f'NS {n} -> {a[0]}')
            except Exception as e:
                test['status'] = 'vulnerable'
                test['details'].append(f'NS {n} not resolving: {str(e)}')
        
        return test
    
    def run_all_tests(self):
        self.results['tests'].append(self.check_axfr())
        self.results['tests'].extend(self.check_spf_dmarc())
        self.results['tests'].append(self.check_wildcard())
        self.results['tests'].append(self.check_mx())
        self.results['tests'].append(self.check_cname_takeover())
        self.results['tests'].append(self.check_ns_health())
        
        # Calculate statistics
        total = len(self.results['tests'])
        vulnerable = sum(1 for t in self.results['tests'] if t['status'] == 'vulnerable')
        warning = sum(1 for t in self.results['tests'] if t['status'] == 'warning')
        safe = sum(1 for t in self.results['tests'] if t['status'] == 'safe')
        
        self.results['stats'] = {
            'total': total,
            'vulnerable': vulnerable,
            'warning': warning,
            'safe': safe,
            'score': int((safe / total) * 100) if total > 0 else 0
        }
        
        return self.results

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        nameserver = data.get('nameserver', '127.0.0.1').strip()
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
        
        scanner = DNSScanner(domain, nameserver)
        results = scanner.run_all_tests()
        
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
