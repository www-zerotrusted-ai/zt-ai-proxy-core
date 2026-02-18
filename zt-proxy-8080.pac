function FindProxyForURL(url, host) {
    // Enhanced PAC file with debugging for ZTProxy (Port 8080)
    
    // Domain routing is server-managed (via extension dynamic PAC); leave empty here.
    var aiDomains = [];
        var proxyAddr = typeof ZT_PROXY_ADDR !== 'undefined' ? ZT_PROXY_ADDR : "localhost:8080";

    // Normalize host (remove port if present)
    var cleanHost = host.split(':')[0].toLowerCase();
    
    // Check each AI domain
    for (var i = 0; i < aiDomains.length; i++) {
        var domain = aiDomains[i].toLowerCase();
        
        // Exact match or subdomain match
            if (cleanHost === domain || 
                cleanHost.endsWith('.' + domain) ||
                domain.indexOf(cleanHost) !== -1) {
                console.log("PAC: Routing " + host + " through proxy " + proxyAddr);
                return "PROXY " + proxyAddr;
        }
    }
    
    // Special handling for certificate installation
    if (cleanHost === "mitm.it" || cleanHost === "mitmproxy.org") {
        console.log("PAC: Direct connection for " + host + " (certificate site)");
        return "DIRECT";
    }
    
    // Default: direct connection for all other sites
    console.log("PAC: Direct connection for " + host);
    return "DIRECT";
}
