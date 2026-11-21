/* OpenPlayX UI kit — theme + small behaviours for Basecoat pages.
   Load synchronously in <head> (after the CSS) so the theme applies before first paint.
   Theme preference: toggle choice → ?theme=light|dark → localStorage "opx-theme" → OS setting (default).
   Put <button data-theme-toggle> anywhere to get a system/light/dark switch.
   Toggle labels follow <html lang> and refresh on opx-i18n's 'opx:langchange' event. */
(function(){
  'use strict';
  var root=document.documentElement,mq=window.matchMedia('(prefers-color-scheme: dark)'),chosen=null;
  function pref(){
    if(chosen)return chosen;
    try{var q=new URLSearchParams(location.search).get('theme');if(q==='light'||q==='dark')return q;}catch(e){}
    try{var s=localStorage.getItem('opx-theme');if(s==='light'||s==='dark')return s;}catch(e){}
    return 'system';
  }
  /* [data-theme-toggle] buttons cycle system → light → dark; the kit fills in icon and label. */
  var ICONS={system:'<rect width="20" height="14" x="2" y="3" rx="2"/><path d="M8 21h8M12 17v4"/>',light:'<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/>',dark:'<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/>'};
  var NEXT={system:'light',light:'dark',dark:'system'};
  function labels(){return /^zh/i.test(root.lang||'')?{system:'跟随系统',light:'浅色',dark:'深色',prefix:'主题：'}:{system:'System',light:'Light',dark:'Dark',prefix:'Theme: '};}
  function renderToggles(force){
    var p=pref(),l=labels(),state=p+'|'+(root.lang||'');
    document.querySelectorAll('[data-theme-toggle]').forEach(function(button){
      if(force!==true&&button.getAttribute('data-theme-state')===state)return;
      button.setAttribute('data-theme-state',state);
      button.innerHTML='<svg class="opx-icon" viewBox="0 0 24 24" aria-hidden="true">'+ICONS[p]+'</svg>'+(button.hasAttribute('data-theme-toggle-text')?'<span>'+l[p]+'</span>':'');
      button.setAttribute('aria-label',l.prefix+l[p]);
      button.title=l.prefix+l[p];
    });
  }
  function apply(){var p=pref();root.classList.toggle('dark',p==='dark'||(p==='system'&&mq.matches));root.setAttribute('data-theme-preference',p);renderToggles();}
  apply();
  if(mq.addEventListener)mq.addEventListener('change',apply);
  function set(v){chosen=v==='light'||v==='dark'?v:'system';try{if(chosen!=='system')localStorage.setItem('opx-theme',chosen);else localStorage.removeItem('opx-theme');}catch(e){}apply();}
  window.opxTheme={get:pref,set:set,cycle:function(){set(NEXT[pref()]);}};
  document.addEventListener('click',function(event){var t=event.target.closest&&event.target.closest('[data-theme-toggle]');if(t){event.preventDefault();window.opxTheme.cycle();}});
  window.addEventListener('storage',function(event){if(event.key==='opx-theme'){chosen=null;apply();}});
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',renderToggles);
  document.addEventListener('opx:langchange',function(){renderToggles(true);});

  /* Basecoat .sidebar: open on desktop, off-canvas below 768px.
     Any [data-sidebar-toggle] button toggles it; links/buttons inside close it on mobile. */
  function initSidebars(){
    var narrow=window.matchMedia('(max-width: 767px)');
    document.querySelectorAll('.sidebar').forEach(function(bar){
      if(bar.hasAttribute('data-sidebar-initialized'))return;
      function set(open){bar.setAttribute('aria-hidden',String(!open));if(open)bar.removeAttribute('inert');else bar.setAttribute('inert','');}
      set(!narrow.matches);
      bar.addEventListener('click',function(event){
        if(!narrow.matches)return;
        var nav=bar.querySelector(':scope > nav');
        if(event.target.closest('a,button')||(nav&&!nav.contains(event.target)))set(false);
      });
      if(narrow.addEventListener)narrow.addEventListener('change',function(){set(!narrow.matches);});
      bar.opxToggle=function(){set(bar.getAttribute('aria-hidden')==='true');};
      bar.setAttribute('data-sidebar-initialized','true');
    });
    document.querySelectorAll('[data-sidebar-toggle]').forEach(function(button){
      if(button.hasAttribute('data-opx-bound'))return;
      button.setAttribute('data-opx-bound','');
      button.addEventListener('click',function(){var bar=document.querySelector('.sidebar');if(bar&&bar.opxToggle)bar.opxToggle();});
    });
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',initSidebars);else initSidebars();
})();
