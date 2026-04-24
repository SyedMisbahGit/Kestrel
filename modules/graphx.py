import requests
import json
from urllib.parse import urljoin

class GraphQLSniper:
    def __init__(self, target):
        self.target = target
        # Common GraphQL endpoints
        self.endpoints = ['/graphql', '/api/graphql', '/v1/graphql', '/v2/graphql', '/query']
        # The universal Introspection Query payload
        self.introspection_query = {
            "query": "\n    query IntrospectionQuery {\n      __schema {\n        queryType { name }\n        mutationType { name }\n        subscriptionType { name }\n        types {\n          ...FullType\n        }\n        directives {\n          name\n          description\n          locations\n          args {\n            ...InputValue\n          }\n        }\n      }\n    }\n\n    fragment FullType on __Type {\n      kind\n      name\n      description\n      fields(includeDeprecated: true) {\n        name\n        description\n        args {\n          ...InputValue\n        }\n        type {\n          ...TypeRef\n        }\n        isDeprecated\n        deprecationReason\n      }\n      inputFields {\n        ...InputValue\n      }\n      interfaces {\n        ...TypeRef\n      }\n      enumValues(includeDeprecated: true) {\n        name\n        description\n        isDeprecated\n        deprecationReason\n      }\n      possibleTypes {\n        ...TypeRef\n      }\n    }\n\n    fragment InputValue on __InputValue {\n      name\n      description\n      type { ...TypeRef }\n      defaultValue\n    }\n\n    fragment TypeRef on __Type {\n      kind\n      name\n      ofType {\n        kind\n        name\n        ofType {\n          kind\n          name\n          ofType {\n            kind\n            name\n            ofType {\n              kind\n              name\n              ofType {\n                kind\n                name\n                ofType {\n                  kind\n                  name\n                  ofType {\n                    kind\n                    name\n                  }\n                }\n              }\n            }\n          }\n        }\n      }\n    }\n  "
        }

    def hunt(self, live_hosts):
        print(f"[*] GRAPH-X: Hunting for exposed GraphQL Introspection on {len(live_hosts)} hosts...")
        vulnerabilities = []

        for host in live_hosts:
            for endpoint in self.endpoints:
                url = urljoin(host, endpoint)
                try:
                    res = requests.post(url, json=self.introspection_query, timeout=5)
                    if res.status_code == 200 and '"__schema"' in res.text:
                        print(f"  [+] [CRITICAL] GraphQL Introspection Exposed: {url}")
                        schema_data = res.json()
                        
                        # Extract Mutations (The dangerous stuff)
                        mutations = []
                        try:
                            types = schema_data['data']['__schema']['types']
                            for t in types:
                                if t['name'] == 'Mutation':
                                    for field in t.get('fields', []):
                                        mutations.append(field['name'])
                        except KeyError:
                            pass
                            
                        vuln = {
                            "type": "VULN",
                            "name": "GraphQL Introspection Leak",
                            "matched-at": url,
                            "info": {
                                "severity": "HIGH",
                                "description": f"Exposed schema revealed {len(mutations)} underlying mutations.",
                                "mutations_leaked": mutations[:10] # Log top 10 mutations
                            }
                        }
                        vulnerabilities.append(vuln)
                        break # Found the endpoint, no need to check other paths on this host
                except requests.exceptions.RequestException:
                    continue
                    
        return vulnerabilities
