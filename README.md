# Gosh Dang Vulnerable C# Application

## ⚠️ Security Warning

**This is a deliberately vulnerable web application for educational purposes only!**

- **NEVER deploy this application in production environments**
- **NEVER expose it to untrusted networks or the internet**
- **DO NOT use this as a security guide or reference**
- **Only use in isolated, controlled learning environments**

This application contains intentional security vulnerabilities designed for educational purposes, security training, and penetration testing practice.

## About This Application

GDVCSharp (Goat Damn Vulnerable C#) is a deliberately vulnerable .NET 8 Web API application that showcases common web application security vulnerabilities. It serves as a practical learning tool for:

- Security professionals learning about web application vulnerabilities
- Developers understanding secure coding practices
- Penetration testers practicing vulnerability identification and exploitation
- Security trainers demonstrating real-world attack scenarios

## Vulnerabilities Included

The application demonstrates the following major vulnerability categories:

### 1. **Server-Side Request Forgery (SSRF)**
- Unvalidated URL requests allowing internal network access
- Cloud metadata service exploitation
- POST-based SSRF attacks

### 2. **Authorization Bypass**
- Missing return statements in authorization checks
- Client-side role parameter injection
- Cookie-based authentication bypass
- HTTP method confusion

### 3. **Regular Expression Denial of Service (ReDoS)**
- Catastrophic backtracking patterns
- User-controlled regex patterns
- Multiple vulnerable validation endpoints

### 4. **Regular Expression Injection**
- User-supplied regex patterns
- Pattern concatenation vulnerabilities
- Log searching with regex injection

### 5. **Cross-Site Scripting (XSS)**
- Reflected XSS in HTML responses
- XSS in JSON responses
- DOM-based XSS opportunities
- XSS in error messages and feedback forms

### 6. **Hard Coded Secrets**
- API keys and passwords in source code
- Configuration endpoints exposing secrets
- Environment variable exposure
- Backup files containing sensitive information

### 7. **Secrets in GET Request Parameters**
- Authentication credentials in URL parameters
- API keys transmitted via GET requests
- Password exposure in server logs

### 8. **Path Traversal**
- Directory traversal file access
- Unrestricted file uploads
- Directory listing vulnerabilities
- Source code exposure

## Quick Start

### Prerequisites
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- [Docker](https://www.docker.com/) (optional)

### Running with .NET CLI

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Uraxii/gdvcsharp-api.git
   cd gdvcsharp-api
   ```

2. **Navigate to the application directory:**
   ```bash
   cd app
   ```

3. **Restore dependencies:**
   ```bash
   dotnet restore
   ```

4. **Run the application:**
   ```bash
   dotnet run
   ```

5. **Access the application:**
   - Application: http://localhost:5000
   - Swagger UI: http://localhost:5000/swagger
   - Vulnerability list: http://localhost:5000

### Running with Docker

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Uraxii/gdvcsharp-api.git
   cd gdvcsharp-api
   ```

2. **Build and run with Docker Compose:**
   ```bash
   docker-compose up --build
   ```

3. **Access the application:**
   - Application: http://localhost:5000
   - Target server (for SSRF): http://localhost:8080

## API Endpoints

### Vulnerable Endpoints

The application exposes 23+ vulnerable endpoints across different categories:

- **SSRF**: `/api/ssrf/vulnerable`, `/api/ssrf/post-vulnerable`
- **Auth Bypass**: `/api/authbypass/admin/*`
- **ReDoS**: `/api/regex/validate`, `/api/regex/search`
- **XSS**: `/api/xss/search`, `/api/xss/profile`, `/api/xss/feedback`
- **Secrets**: `/api/hardcodedsecrets/config/vuln`, `/api/hardcodedsecrets/auth/vuln`
- **Path Traversal**: `/api/pathtraversal/vuln`, `/api/pathtraversal/list/vuln`

### Secure Endpoints

For comparison, the application also includes secure implementations:

- **Secure Path Traversal**: `/api/pathtraversal/solution`
- **Secure Configuration**: `/api/hardcodedsecrets/config/solution`
- **Secure Authentication**: `/api/hardcodedsecrets/auth/solution`

## Testing the Vulnerabilities

### Example Attacks

**SSRF Attack:**
```bash
curl "http://localhost:5000/api/ssrf/vulnerable?url=http://169.254.169.254/latest/meta-data/"
```

**Authorization Bypass:**
```bash
curl "http://localhost:5000/api/authbypass/admin/dashboard?userId=123&role=admin"
```

**ReDoS Attack:**
```bash
curl "http://localhost:5000/api/regex/validate?input=aaaaaaaaaaaaaaaaaaaaac"
```

**XSS Attack:**
```bash
curl "http://localhost:5000/api/xss/search?query=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"
```

**Path Traversal Attack:**
```bash
curl "http://localhost:5000/api/pathtraversal/vuln?filename=../../../etc/passwd"
```

## Documentation

Comprehensive documentation for each vulnerability type is available in the `documentation/` directory:

### Vulnerability Deep Dives
- **[Authorization Bypass](documentation/authorization_bypass.md)** - Complete analysis and fixes
- **[Cross-Site Scripting (XSS)](documentation/xss.md)** - XSS variants and prevention
- **[Hard Coded Secrets](documentation/hardcoded_secrets.md)** - Secret management best practices
- **[Path Traversal](documentation/path_traversal.md)** - File access vulnerabilities
- **[Regular Expression Denial of Service](documentation/redos.md)** - ReDoS attacks and mitigation
- **[Regular Expression Injection](documentation/regex_injection.md)** - Pattern injection attacks
- **[Secrets in GET Requests](documentation/secrets_in_get_request.md)** - Authentication vulnerabilities
- **[Server-Side Request Forgery](documentation/ssrf.md)** - SSRF exploitation and prevention

Each documentation file includes:
- Root cause analysis
- Attack scenarios and examples
- Impact assessment
- Complete fix implementations
- Testing procedures

---

**Remember: This application is intentionally vulnerable. Use responsibly and only for educational purposes!**
