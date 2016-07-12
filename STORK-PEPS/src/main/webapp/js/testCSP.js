// Testing the CSP is active
function testCSP() {
    try {
        eval("1=1");
        document.getElementById("cspMessage").innerHTML="<h2>Your browser version is outdated to support latest security features, please upgrade it</h2>";
    } catch (e) {
        // CSP is enabled
    }
}
window.addEventListener('load', testCSP());