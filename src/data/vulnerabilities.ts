export interface Vulnerability {
  number: number;
  title: string;
  severity: "Low" | "Medium" | "High" | "Critical";
  summary: string;
  code: string;
  do: string;
  dont: string;
  category?: string;
}

export const vulnerabilities: Vulnerability[] = [
  {
    number: 1,
    title: "Buffer Overflow",
    severity: "Critical",
    summary: "Input validation failure can lead to code execution.",
    code: "char buf[8];\ngets(buf);",
    do: "Use strncpy, validate input",
    dont: "Avoid unsafe functions like gets()",
    category: "Memory Safety"
  },
  {
    number: 2,
    title: "SQL Injection",
    severity: "High",
    summary: "Unsanitized user input in database queries.",
    code: "query = \"SELECT * FROM users WHERE id = \" + userId;",
    do: "Use prepared statements",
    dont: "Never concatenate user input into queries",
    category: "Input Validation"
  },
  {
    number: 3,
    title: "Cross-Site Scripting (XSS)",
    severity: "High",
    summary: "Malicious scripts injected into web pages.",
    code: "innerHTML = userInput;",
    do: "Sanitize and validate all user input",
    dont: "Don't trust user input directly",
    category: "Web Security"
  },
  {
    number: 4,
    title: "Use After Free",
    severity: "Critical",
    summary: "Accessing memory after it has been freed.",
    code: "free(ptr);\n*ptr = 0x41414141;",
    do: "Set pointers to NULL after freeing",
    dont: "Don't access freed memory",
    category: "Memory Safety"
  },
  {
    number: 5,
    title: "Integer Overflow",
    severity: "Medium",
    summary: "Arithmetic operations exceed data type limits.",
    code: "unsigned int size = user_size + 10;",
    do: "Check for overflow before operations",
    dont: "Assume arithmetic operations won't overflow",
    category: "Arithmetic"
  },
  {
    number: 6,
    title: "Command Injection",
    severity: "Critical",
    summary: "Execution of arbitrary system commands.",
    code: "system(\"ls \" + userInput);",
    do: "Use safe APIs, validate input",
    dont: "Don't pass user input to system calls",
    category: "Input Validation"
  },
  {
    number: 7,
    title: "Race Condition",
    severity: "Medium",
    summary: "Multiple threads access shared data unsafely.",
    code: "if (balance > amount) {\n  balance -= amount;\n}",
    do: "Use proper synchronization mechanisms",
    dont: "Assume single-threaded execution",
    category: "Concurrency"
  },
  {
    number: 8,
    title: "Path Traversal",
    severity: "High",
    summary: "Access files outside intended directory.",
    code: "file = open(\"docs/\" + filename);",
    do: "Validate and sanitize file paths",
    dont: "Trust user-supplied file paths",
    category: "Input Validation"
  },
  {
    number: 9,
    title: "Insecure Deserialization",
    severity: "High",
    summary: "Untrusted data deserialization leads to code execution.",
    code: "obj = pickle.loads(user_data);",
    do: "Use safe serialization formats",
    dont: "Deserialize untrusted data",
    category: "Data Processing"
  },
  {
    number: 10,
    title: "Hardcoded Credentials",
    severity: "Medium",
    summary: "Sensitive credentials embedded in source code.",
    code: "password = \"admin123\";",
    do: "Use environment variables or secure vaults",
    dont: "Hardcode credentials in source",
    category: "Authentication"
  },
  {
    number: 11,
    title: "Format String Bug",
    severity: "High",
    summary: "User input used as format string parameter.",
    code: "printf(user_input);",
    do: "Use fixed format strings",
    dont: "Pass user input as format string",
    category: "Input Validation"
  },
  {
    number: 12,
    title: "TOCTOU (Time-of-Check Time-of-Use)",
    severity: "Medium",
    summary: "Race condition between security check and usage.",
    code: "if (access(file, R_OK) == 0) {\n  fd = open(file, O_RDONLY);\n}",
    do: "Use atomic operations",
    dont: "Separate check and use operations",
    category: "Concurrency"
  }
];

export const getSeverityColor = (severity: Vulnerability["severity"]) => {
  switch (severity) {
    case "Low":
      return "severity-low";
    case "Medium":
      return "severity-medium";
    case "High":
      return "severity-high";
    case "Critical":
      return "severity-critical";
    default:
      return "severity-medium";
  }
};

export const getSeverityGlowColor = (severity: Vulnerability["severity"]) => {
  switch (severity) {
    case "Low":
      return "severity-low-glow";
    case "Medium":
      return "severity-medium-glow";
    case "High":
      return "severity-high-glow";
    case "Critical":
      return "severity-critical-glow";
    default:
      return "severity-medium-glow";
  }
};