# 💡 Integration Examples

Real-world examples of using DataGuard Fortress with popular AI frameworks and LLM providers.

## 1️⃣ OpenAI Chat Completion (Python)

Protect your OpenAI API calls with automatic PII scrubbing.

```python
import os
import openai
from typing import Optional

# Configure OpenAI to use DataGuard proxy
openai.api_base = "http://localhost:8080"
openai.api_key = os.getenv("OPENAI_API_KEY")

def chat_with_protection(user_message: str, tenant_id: str = "default") -> str:
    """
    Send a chat message through DataGuard proxy.
    PII will be automatically scrubbed before reaching OpenAI.
    """
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {
                "role": "user",
                "content": user_message,
                "X-DataGuard-Tenant": tenant_id,
            }
        ],
        temperature=0.7,
    )
    return response.choices[0].message.content


# Example: User provides sensitive information
sensitive_input = """
My name is Alice Johnson,
my email is alice@acme.com,
SSN: 123-45-6789,
credit card: 4532-1234-5678-9010
"""

# PII is automatically scrubbed before reaching OpenAI
response = chat_with_protection(sensitive_input, tenant_id="acme-corp")
print(response)
# OpenAI never sees: alice@acme.com, SSN, or credit card
```

---

## 2️⃣ Anthropic Claude (Python)

Integrate DataGuard with Anthropic's Claude API.

```python
import anthropic
import os

# Point client through DataGuard
client = anthropic.Anthropic(
    api_key=os.getenv("ANTHROPIC_API_KEY"),
    base_url="http://localhost:8080",  # DataGuard proxy
)

def analyze_document_safely(document: str, tenant_id: str = "default") -> str:
    """
    Send document to Claude for analysis.
    PII in document will be scrubbed by DataGuard.
    """
    message = client.messages.create(
        model="claude-3-opus-20240229",
        max_tokens=1024,
        headers={
            "X-DataGuard-Tenant": tenant_id,
        },
        messages=[
            {
                "role": "user",
                "content": document,
            }
        ],
    )
    return message.content[0].text


# Example: Customer support document with PII
support_ticket = """
Customer Name: Bob Smith
Email: bob.smith@company.com
Phone: +1-555-0123
Account Number: ACC-123456
API Key: sk-1234567890abcdef

Issue: Cannot access dashboard
"""

# DataGuard scrubs PII before sending to Claude
analysis = analyze_document_safely(
    support_ticket, 
    tenant_id="support-team"
)
print(analysis)
```

---

## 3️⃣ LangChain Integration

Use DataGuard with LangChain for secure LLM applications.

```python
from langchain.llms import OpenAI
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
import os

# Configure LangChain to use DataGuard proxy
os.environ["OPENAI_API_BASE"] = "http://localhost:8080"
os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")

# Create LLM with DataGuard proxy
llm = OpenAI(temperature=0.7)

# Define a chain with a prompt template
template = """
Analyze the following customer feedback and provide sentiment:
{feedback}

Sentiment Analysis:
"""

prompt = PromptTemplate(template=template, input_variables=["feedback"])
chain = LLMChain(llm=llm, prompt=prompt)

# Example: Run chain with sensitive customer data
customer_feedback = """
I'm disappointed with your service.
My account ID is ACC-987654.
I contacted support at customer.care@ourcompany.com.
My phone number is 555-0123.
"""

# PII is scrubbed before reaching OpenAI via LangChain
result = chain.run(feedback=customer_feedback)
print(result)
```

---

## 4️⃣ LlamaIndex with DataGuard

Secure document indexing and retrieval.

```python
from llama_index import GPTVectorStoreIndex, SimpleDirectoryReader
from llama_index.llms import OpenAI
import os

# Configure OpenAI via DataGuard
os.environ["OPENAI_API_BASE"] = "http://localhost:8080"

# Load documents (e.g., PDFs, text files)
documents = SimpleDirectoryReader("./documents").load_data()

# Create index
llm = OpenAI(model="gpt-4", temperature=0.7)
index = GPTVectorStoreIndex.from_documents(documents, llm=llm)

# Example: Query with sensitive information
query = """
Find information about John Doe (john@example.com)
Account: ACC-555888
"""

# DataGuard scrubs PII before processing
query_engine = index.as_query_engine()
response = query_engine.query(query)
print(response)
```

---

## 5️⃣ Multi-Tenant Rate Limiting

Protect multiple teams with per-tenant rate limits.

```python
import httpx
import asyncio
from typing import Optional

class DataGuardClient:
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url
        self.client = httpx.AsyncClient()
    
    async def query(
        self,
        tenant_id: str,
        messages: list,
        model: str = "gpt-4",
    ) -> dict:
        """
        Send query with tenant-specific rate limiting.
        Each tenant has its own rate limit (configured in tenants/TENANT_ID.yaml).
        """
        headers = {
            "X-DataGuard-Tenant": tenant_id,
            "Content-Type": "application/json",
        }
        
        payload = {
            "model": model,
            "messages": messages,
        }
        
        response = await self.client.post(
            f"{self.base_url}/v1/chat/completions",
            json=payload,
            headers=headers,
        )
        
        if response.status_code == 429:
            raise Exception(f"Rate limit exceeded for tenant: {tenant_id}")
        
        return response.json()


# Example: Multiple tenants with different limits
async def main():
    client = DataGuardClient()
    
    # Tenant 1: acme-corp (20 req/sec)
    result1 = await client.query(
        tenant_id="acme-corp",
        messages=[{"role": "user", "content": "Hello"}],
    )
    
    # Tenant 2: startup-inc (5 req/sec)
    result2 = await client.query(
        tenant_id="startup-inc",
        messages=[{"role": "user", "content": "Hi"}],
    )
    
    print(result1, result2)

asyncio.run(main())
```

---

## 6️⃣ Audit Log Monitoring

Access audit logs for compliance and debugging.

```python
import json
from pathlib import Path
from datetime import datetime

class AuditLogReader:
    def __init__(self, log_file: str = "./logs/audit.jsonl"):
        self.log_file = Path(log_file)
    
    def read_logs(self, tenant_id: Optional[str] = None) -> list:
        """Read audit logs (JSONL format)."""
        logs = []
        with open(self.log_file) as f:
            for line in f:
                entry = json.loads(line)
                if tenant_id is None or entry.get("tenant") == tenant_id:
                    logs.append(entry)
        return logs
    
    def pii_summary(self) -> dict:
        """Get summary of PII detected."""
        summary = {}
        for entry in self.read_logs():
            pii_type = entry.get("pii_detected", {})
            for pii_key, count in pii_type.items():
                summary[pii_key] = summary.get(pii_key, 0) + count
        return summary
    
    def blocked_requests(self) -> list:
        """Get all blocked requests."""
        blocked = []
        for entry in self.read_logs():
            if entry.get("action") == "BLOCKED":
                blocked.append(entry)
        return blocked


# Example: Monitor audit logs
reader = AuditLogReader()

# Show all logs for acme-corp
acme_logs = reader.read_logs(tenant_id="acme-corp")
print(f"acme-corp requests: {len(acme_logs)}")

# Show PII detection summary
pii_summary = reader.pii_summary()
print("PII Detected:")
for pii_type, count in pii_summary.items():
    print(f"  {pii_type}: {count}")

# Show blocked requests
blocked = reader.blocked_requests()
print(f"Blocked requests: {len(blocked)}")
```

---

## 7️⃣ Docker Compose Stack

Run DataGuard with Redis, monitoring, and logging.

```yaml
version: '3.8'

services:
  dataguard:
    build: .
    ports:
      - "8080:8080"
    environment:
      DG_LOG_LEVEL: INFO
      DG_REDIS_URL: redis://redis:6379/0
    depends_on:
      - redis
    volumes:
      - ./config.yaml:/app/config.yaml
      - ./tenants:/app/tenants
      - ./logs:/app/logs
    networks:
      - dataguard-net

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    networks:
      - dataguard-net

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    networks:
      - dataguard-net

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      GF_SECURITY_ADMIN_PASSWORD: admin
    volumes:
      - grafana_data:/var/lib/grafana
    networks:
      - dataguard-net

volumes:
  redis_data:
  grafana_data:

networks:
  dataguard-net:
    driver: bridge
```

---

## 8️⃣ Custom PII Pattern (Tenant-Specific)

Add custom regex patterns for your organization.

```yaml
# tenants/acme-corp.yaml
tenant_id: acme-corp
name: Acme Corporation

scrubber:
  enabled: true
  min_confidence: 0.85
  
  # Built-in patterns: email, SSN, credit cards, API keys, etc. (52 total)
  
  # Custom patterns for Acme:
  extra_presets:
    - name: employee_id
      pattern: '\bEMP-\d{6}\b'
      replacement: "[REDACTED_EMP_ID]"
      description: "Acme employee ID format"
    
    - name: internal_ticket
      pattern: '\bTICKET-\d{8}\b'
      replacement: "[REDACTED_TICKET]"
      description: "Internal ticket number"
    
    - name: internal_domain
      pattern: '@acme\.internal'
      replacement: "@[REDACTED_DOMAIN]"
      description: "Internal domain"
    
    - name: client_name
      pattern: '\b(?:Alice Johnson|Bob Smith|Charlie Brown)\b'
      replacement: "[REDACTED_CLIENT]"
      description: "Sensitive client names"

rate_limit:
  rate: 20.0
  capacity: 100
  per_minute: 1200
```

---

## 9️⃣ Kubernetes Deployment

Deploy DataGuard in Kubernetes.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dataguard-fortress
  namespace: security
spec:
  replicas: 3
  selector:
    matchLabels:
      app: dataguard-fortress
  template:
    metadata:
      labels:
        app: dataguard-fortress
    spec:
      containers:
      - name: dataguard
        image: dataguard-fortress:latest
        ports:
        - containerPort: 8080
        env:
        - name: DG_REDIS_URL
          value: redis://redis-service:6379/0
        - name: DG_LOG_LEVEL
          value: INFO
        volumeMounts:
        - name: config
          mountPath: /app/config.yaml
          subPath: config.yaml
        - name: tenants
          mountPath: /app/tenants
        - name: logs
          mountPath: /app/logs
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 10
      
      volumes:
      - name: config
        configMap:
          name: dataguard-config
      - name: tenants
        configMap:
          name: dataguard-tenants
      - name: logs
        emptyDir: {}

---
apiVersion: v1
kind: Service
metadata:
  name: dataguard-service
  namespace: security
spec:
  selector:
    app: dataguard-fortress
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8080
  type: ClusterIP
```

---

## 🔟 Testing & Validation

Test DataGuard with real PII.

```python
import requests
import json

def test_dataguard_scrubbing():
    """Test that DataGuard properly scrubs PII."""
    
    test_cases = [
        {
            "name": "Email detection",
            "input": "Contact me at john.doe@acme.com",
            "should_contain": "[REDACTED_EMAIL]",
        },
        {
            "name": "SSN detection",
            "input": "My SSN is 123-45-6789",
            "should_contain": "[REDACTED_SSN]",
        },
        {
            "name": "Credit card detection",
            "input": "Visa: 4532-1234-5678-9010",
            "should_contain": "[REDACTED_CC]",
        },
        {
            "name": "API key detection",
            "input": "API key: sk-1234567890abcdef",
            "should_contain": "[REDACTED_APIKEY]",
        },
    ]
    
    for test in test_cases:
        response = requests.post(
            "http://localhost:8080/api/scrub",
            json={"text": test["input"]},
            headers={"X-DataGuard-Tenant": "default"},
        )
        
        result = response.json()
        scrubbed = result.get("scrubbed_text", "")
        
        if test["should_contain"] in scrubbed:
            print(f"✅ {test['name']}: PASS")
        else:
            print(f"❌ {test['name']}: FAIL")
            print(f"   Expected: {test['should_contain']}")
            print(f"   Got: {scrubbed}")


if __name__ == "__main__":
    test_dataguard_scrubbing()
```

---

<div align="center">

**Need more examples?** [Start a discussion](../../discussions) or [open an issue](../../issues).

</div>
