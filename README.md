# for-david-oidc-generate-nonce

Repoed doing simple oidc login. 


1. Run the app  
2. Set a break point in the class NeedsServiceProviderOpenIdConnectProtocolValidator, or SimpleOpenIdConnectProtocolValidator depending on which one you want.  
3. click on ```"Secure"``` to trigger the login  


The SimpleOpenIdConnectProtocolValidator works when it is directly added via good ole new()
The NeedsServiceProviderOpenIdConnectProtocolValidator is in never-never land :(

Herb
