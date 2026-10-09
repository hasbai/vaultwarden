// The stock Web Vault SSO protocol remains unchanged; select our single IdP.
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
