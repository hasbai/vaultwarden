// The stock Web Vault SSO protocol remains unchanged; select our single IdP.
// External clients supply their own PKCE and callback state. Preserve them
// while selecting the provider before the stock SSO component initializes.
const [ssoRoute, ssoQuery = ''] = location.hash.slice(1).split('?');
const ssoParams = new URLSearchParams(ssoQuery);
if (ssoRoute === '/sso' &&
    ['clientId', 'redirectUri', 'state', 'codeChallenge'].every(key => ssoParams.get(key)) &&
    !['identifier', 'code', 'error', 'error_description'].some(key => ssoParams.has(key))) {
  ssoParams.set('identifier', 'hasbai');
  history.replaceState(null, '', `${location.pathname}${location.search}#/sso?${ssoParams}`);
}
document.addEventListener('click',event=>{
  if(event.target.closest?.('.vw-sso-login')) {
    event.preventDefault();event.stopImmediatePropagation();
    location.hash='/sso?identifier=hasbai';
  }
},true);
new MutationObserver(()=>{
  const button=document.querySelector('.vw-sso-login');
  if(button && button.textContent.trim()!=='使用北极小站登录') button.textContent='使用北极小站登录';
}).observe(document.documentElement,{subtree:true,childList:true});
