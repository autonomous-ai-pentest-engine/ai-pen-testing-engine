import ast
from pathlib import Path
from typing import Dict, List, Any, Union

class SecurityVerificationEngine:
    def __init__(self) -> None:
        """Initialize the engine with target dangerous sinks and boundary tests."""
        self.dangerous_sinks = {'eval', 'exec', 'system'}
        self.boundary_inputs = [
            "<script>alert(1)</script>",
            "'; DROP TABLE users; --",
            "../../../etc/passwd",
            "$(cat /etc/shadow)",
            "{{ config.items() }}"
        ]

    def perceive(self, file_path: Union[str, Path]) -> List[Dict[str, Any]]:
        """
        Securely parses a target file into an AST and scans for dangerous function/attribute calls.
        """
        findings: List[Dict[str, Any]] = []
        path = Path(file_path)
        
        if not path.exists() or not path.is_file():
            return findings

        try:
            content = path.read_text(encoding='utf-8')
            tree = ast.parse(content, filename=str(path))
        except (SyntaxError, UnicodeDecodeError):
            return findings

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in self.dangerous_sinks:
                        findings.append({
                            'type': 'dangerous_function_call',
                            'target': node.func.id,
                            'line': node.lineno
                        })
                elif isinstance(node.func, ast.Attribute):
                    if node.func.attr in self.dangerous_sinks:
                        findings.append({
                            'type': 'dangerous_attribute_call',
                            'target': node.func.attr,
                            'line': node.lineno
                        })
        return findings

    def plan(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Evaluates AST findings and maps them into a structured threat mitigation matrix.
        """
        matrix: Dict[str, Any] = {
            'risk_level': 'LOW',
            'threats': [],
            'mitigation_steps': []
        }
        
        if not findings:
            return matrix
            
        matrix['risk_level'] = 'HIGH' if any(
            f.get('target') in self.dangerous_sinks for f in findings
        ) else 'MEDIUM'
        
        for finding in findings:
            target = finding.get('target', 'unknown')
            line = finding.get('line', 'Unknown')
            
            matrix['threats'].append({
                'identifier': f"VULN-{str(target).upper()}",
                'location': f"Line {line}",
                'description': f"Un-sanitized use of '{target}' detected."
            })
            
            matrix['mitigation_steps'].append(
                f"Replace '{target}' at line {line} with a safe alternative or implement strict input sanitization."
            )
            
        return matrix

    def test(self) -> Dict[str, Any]:
        """
        Simulates boundary-test input strings against a validation filter.
        """
        results: Dict[str, Any] = {
            'total': len(self.boundary_inputs), 
            'passed': 0, 
            'failed': 0, 
            'details': []
        }
        
        for test_input in self.boundary_inputs:
            # Simulate a basic validation engine checking the input.
            # A robust filter should block inputs containing these characters.
            blocked = any(char in test_input for char in ['<', '>', ';', '$', '{', '}'])
            status = 'BLOCKED' if blocked else 'ALLOWED'
            
            if status == 'BLOCKED':
                results['passed'] += 1
            else:
                results['failed'] += 1
                
            results['details'].append({
                'input': test_input,
                'status': status
            })
            
        return results

    def remediate(self, test_results: Dict[str, Any], plan_matrix: Dict[str, Any]) -> str:
        """
        Aggregates results and generates a Markdown Pass/Fail report summary.
        """
        report = [
            "# Security Verification Report",
            "",
            "## 1. Threat Mitigation Matrix",
            f"**Overall Risk Level:** {plan_matrix.get('risk_level', 'UNKNOWN')}",
            ""
        ]
        
        threats = plan_matrix.get('threats', [])
        if threats:
            report.append("### Detected Vulnerabilities")
            for threat in threats:
                report.append(f"- **{threat.get('identifier')}** ({threat.get('location')}): {threat.get('description')}")
            report.append("")
            
            report.append("### Recommended Mitigations (Guardrail Patches)")
            for step in plan_matrix.get('mitigation_steps', []):
                report.append(f"- {step}")
            report.append("")
        else:
            report.append("No vulnerabilities detected in the analyzed code.\n")
            
        report.append("## 2. Boundary Test Simulation Results")
        report.append(f"**Passed Filters (Blocked):** {test_results.get('passed')}/{test_results.get('total')}")
        report.append(f"**Failed Filters (Allowed):** {test_results.get('failed')}/{test_results.get('total')}")
        report.append("")
        
        for detail in test_results.get('details', []):
            report.append(f"- Input: `{detail.get('input')}` -> **{detail.get('status')}**")
            
        report.append("")
        report.append("## 3. Final Assessment")
        
        passed_tests = test_results.get('failed') == 0
        no_threats = len(threats) == 0
        
        if passed_tests and no_threats:
            report.append("**Status:** ✅ PASS")
            report.append("Code is cleared for further CI/CD stages.")
        else:
            report.append("**Status:** ❌ FAIL")
            report.append("Please address the flagged issues and ensure all boundary tests are blocked by the validation engine.")
            
        return "\n".join(report)