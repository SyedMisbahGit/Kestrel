import re
import os

class WasmExtractor:
    def __init__(self, oracle=None):
        self.oracle = oracle
        # Regex to find printable ASCII strings longer than 8 characters (filters out binary noise)
        self.string_pattern = re.compile(b'[ -~]{8,}')
        
    def extract_secrets(self, file_path):
        secrets = set()
        if not os.path.exists(file_path):
            return secrets
            
        with open(file_path, 'rb') as f:
            header = f.read(4)
            if header != b'\x00asm':
                return secrets # Not a valid Wasm file
                
            f.seek(0)
            binary_data = f.read()
            
        print(f"  [*] BLACKSMITH: Shattering compiled binary {os.path.basename(file_path)}...")
        
        # Extract all readable strings from the binary
        raw_strings = self.string_pattern.findall(binary_data)
        
        for raw in raw_strings:
            try:
                decoded = raw.decode('utf-8')
                # Strict length constraints for tokens
                if 16 < len(decoded) < 64:
                    from modules.cortex import calculate_shannon_entropy # Lazy import to avoid circular dependency
                    entropy = calculate_shannon_entropy(decoded)
                    
                    if entropy > 4.5:
                        # Ask the ML Oracle
                        if self.oracle:
                            prediction = self.oracle.predict([[len(decoded), entropy]])[0]
                            if prediction == 1:
                                masked = decoded[:4] + "********" + decoded[-4:] if len(decoded) > 8 else "****"
                                secrets.add((masked, round(entropy, 2)))
                        else:
                            masked = decoded[:4] + "********" + decoded[-4:] if len(decoded) > 8 else "****"
                            secrets.add((masked, round(entropy, 2)))
            except UnicodeDecodeError:
                continue
                
        return secrets
