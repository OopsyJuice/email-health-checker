import re
from typing import Dict, List
from email import parser
from email.parser import HeaderParser
from datetime import datetime

class EmailHeaderAnalyzer:
    """Analyzes email headers to determine authenticity and trace routing."""

    def __init__(self, raw_headers: str):
        self.raw_headers = raw_headers
        self.parsed_headers = {}
        self.authentication_results = []
        self.received_chain = []
        self.analysis = {}
        self.recommendations = []

    def analyze(self) -> Dict:
        """Performs the email header analysis and returns results."""
        try:
            # Parse the headers
            parser = HeaderParser()
            self.parsed_headers = parser.parsestr(self.raw_headers)
            
            # Analyze different components
            self._analyze_authentication()
            self._analyze_received_chain()
            self._analyze_spam_headers()
            self._analyze_message_info()
            self._generate_recommendations()

            return {
                'status': 'success',
                'authentication': self.authentication_results,
                'routing': self.received_chain,
                'message_info': self.analysis,
                'recommendations': self.recommendations,
                'spam_score': self._calculate_spam_score()
            }

        except Exception as e:
            return {
                'status': 'error',
                'message': f'Failed to analyze headers: {str(e)}'
            }

    def _analyze_authentication(self):
        """Analyzes authentication headers (SPF, DKIM, DMARC)."""
        auth_results = self.parsed_headers.get('Authentication-Results', '')
        
        # SPF Analysis
        spf_match = re.search(r'spf=(\w+)', auth_results)
        if spf_match:
            self.authentication_results.append({
                'type': 'SPF',
                'result': spf_match.group(1),
                'status': 'pass' if spf_match.group(1) == 'pass' else 'fail'
            })
        
        # DKIM Analysis
        dkim_match = re.search(r'dkim=(\w+)', auth_results)
        if dkim_match:
            self.authentication_results.append({
                'type': 'DKIM',
                'result': dkim_match.group(1),
                'status': 'pass' if dkim_match.group(1) == 'pass' else 'fail'
            })
        
        # DMARC Analysis
        dmarc_match = re.search(r'dmarc=(\w+)', auth_results)
        if dmarc_match:
            self.authentication_results.append({
                'type': 'DMARC',
                'result': dmarc_match.group(1),
                'status': 'pass' if dmarc_match.group(1) == 'pass' else 'fail'
            })

    def _analyze_received_chain(self):
        """Analyzes the Received headers to trace email path."""
        received_headers = self.parsed_headers.get_all('Received', [])
        
        for header in received_headers:
            try:
                # Extract timestamp
                timestamp_match = re.search(r';(.*?)(?:\(.*?\))?\s*$', header)
                timestamp = timestamp_match.group(1).strip() if timestamp_match else "Unknown"
                
                # Extract from and by information
                from_match = re.search(r'from\s+([^\s]+)', header)
                by_match = re.search(r'by\s+([^\s]+)', header)
                
                self.received_chain.append({
                    'from': from_match.group(1) if from_match else "Unknown",
                    'by': by_match.group(1) if by_match else "Unknown",
                    'timestamp': timestamp
                })
            except Exception:
                continue

    def _analyze_spam_headers(self):
        """Analyzes various spam-related headers."""
        spam_score = self.parsed_headers.get('X-Spam-Score', '0')
        spam_status = self.parsed_headers.get('X-Spam-Status', '')
        spam_level = self.parsed_headers.get('X-Spam-Level', '')
        
        self.analysis['spam_headers'] = {
            'score': spam_score,
            'status': spam_status,
            'level': spam_level
        }

    def _analyze_message_info(self):
        """Analyzes basic message information."""
        self.analysis['message_info'] = {
            'message_id': self.parsed_headers.get('Message-ID', ''),
            'date': self.parsed_headers.get('Date', ''),
            'from': self.parsed_headers.get('From', ''),
            'to': self.parsed_headers.get('To', ''),
            'subject': self.parsed_headers.get('Subject', ''),
            'return_path': self.parsed_headers.get('Return-Path', '')
        }

    def _generate_recommendations(self):
        """Generates recommendations based on header analysis."""
        # Check authentication
        for auth in self.authentication_results:
            if auth['status'] != 'pass':
                self.recommendations.append({
                    'severity': 'high',
                    'issue': f'Failed {auth["type"]} Authentication',
                    'impact': f'Email authenticity cannot be verified through {auth["type"]}',
                    'fix': f'Ensure proper {auth["type"]} configuration for the sending domain'
                })

        # Check for suspicious routing
        if len(self.received_chain) > 10:
            self.recommendations.append({
                'severity': 'medium',
                'issue': 'Unusual Routing Path',
                'impact': 'Email went through an unusually high number of servers',
                'fix': 'Investigate the routing chain for potential mail server issues'
            })

        # Check spam indicators
        spam_score = float(self.analysis['spam_headers']['score'] or 0)
        if spam_score > 5:
            self.recommendations.append({
                'severity': 'high',
                'issue': 'High Spam Score',
                'impact': 'Email likely to be marked as spam',
                'fix': 'Review email content and sending practices'
            })

    def _calculate_spam_score(self) -> int:
        """Calculates an overall trustworthiness score."""
        score = 100
        
        # Deduct for failed authentications
        for auth in self.authentication_results:
            if auth['status'] != 'pass':
                score -= 20

        # Deduct for high spam score
        try:
            spam_score = float(self.analysis['spam_headers']['score'] or 0)
            if spam_score > 5:
                score -= 30
            elif spam_score > 3:
                score -= 15
        except ValueError:
            pass

        # Deduct for unusual routing
        if len(self.received_chain) > 10:
            score -= 10

        return max(0, score)  # Ensure score doesn't go below 0 