/* OpenPlayX UI kit — English / Simplified Chinese runtime for the web tools.
   Load synchronously in <head> BEFORE opx-theme.js, then register the page's dictionaries:
     opxI18n.register({en:{...},'zh-CN':{...}})
   Language: ?lang=en|zh-CN (remembered) → localStorage "opx-lang" → browser languages → English.
   Markup:  <h1 data-i18n="login.title">  ·  <input data-i18n-attr="placeholder:login.email,aria-label:login.email">
            data-i18n-vars='{"name":"x"}' fills placeholders; opxI18n.mark(el,key,vars) sets all three.
   Toggle:  any <button data-lang-toggle> switches between the two languages (label filled in).
   Script:  opxI18n.t('key',{name:'x'})  ·  opxI18n.get()  ·  opxI18n.set('en')  ·  'opx:langchange' event. */
(function(){
  'use strict';
  var KEY='opx-lang',LANGS=['en','zh-CN'],NAMES={'en':'English','zh-CN':'中文'},SWITCH={'en':'切换到中文','zh-CN':'Switch to English'};
  var root=document.documentElement,dicts={},current;
  function norm(value){value=String(value||'').toLowerCase();return value.indexOf('zh')===0?'zh-CN':value.indexOf('en')===0?'en':null;}
  function detect(){
    var value=null;
    try{value=norm(new URLSearchParams(location.search).get('lang'));if(value){try{localStorage.setItem(KEY,value);}catch(e){}return value;}}catch(e){}
    try{value=norm(localStorage.getItem(KEY));if(value)return value;}catch(e){}
    var list=navigator.languages&&navigator.languages.length?navigator.languages:[navigator.language];
    for(var i=0;i<list.length;i++){value=norm(list[i]);if(value)return value;}
    return 'en';
  }
  function lookup(dict,key){
    var parts=key.split('.'),value=dict;
    for(var i=0;i<parts.length;i++){if(value==null||typeof value!=='object')return undefined;value=value[parts[i]];}
    return value;
  }
  function format(value,vars){
    if(typeof value!=='string'||!vars)return value;
    return value.replace(/\{(\w+)\}/g,function(match,name){return Object.prototype.hasOwnProperty.call(vars,name)?String(vars[name]):match;});
  }
  /* Missing keys fall back to English, then to the key itself so gaps are visible. */
  function t(key,vars){
    var value=lookup(dicts[current]||{},key);
    if(value===undefined)value=lookup(dicts.en||{},key);
    return value===undefined?key:format(value,vars);
  }
  function has(key){return lookup(dicts[current]||{},key)!==undefined||lookup(dicts.en||{},key)!==undefined;}
  function merge(target,source){
    for(var name in source){
      if(!Object.prototype.hasOwnProperty.call(source,name))continue;
      var value=source[name];
      if(value&&typeof value==='object'&&!Array.isArray(value)){if(!target[name]||typeof target[name]!=='object')target[name]={};merge(target[name],value);}
      else target[name]=value;
    }
  }
  function apply(scope){
    scope=scope||document;
    var nodes=scope.querySelectorAll('[data-i18n]');
    for(var i=0;i<nodes.length;i++){var vars=null;try{vars=JSON.parse(nodes[i].getAttribute('data-i18n-vars')||'null');}catch(e){}nodes[i].textContent=t(nodes[i].getAttribute('data-i18n'),vars);}
    nodes=scope.querySelectorAll('[data-i18n-attr]');
    for(i=0;i<nodes.length;i++){
      var pairs=nodes[i].getAttribute('data-i18n-attr').split(',');
      for(var j=0;j<pairs.length;j++){var at=pairs[j].indexOf(':');if(at>0)nodes[i].setAttribute(pairs[j].slice(0,at).trim(),t(pairs[j].slice(at+1).trim()));}
    }
    nodes=document.querySelectorAll('[data-lang-toggle]');
    var other=current==='en'?'zh-CN':'en';
    for(i=0;i<nodes.length;i++){
      nodes[i].textContent=NAMES[other];
      nodes[i].setAttribute('lang',other);
      nodes[i].setAttribute('aria-label',SWITCH[current]);
      nodes[i].title=SWITCH[current];
    }
  }
  /* Localized text that follows later language switches; key null clears it to plain text. */
  function mark(node,key,vars){
    if(!key){node.removeAttribute('data-i18n');node.removeAttribute('data-i18n-vars');return;}
    node.setAttribute('data-i18n',key);
    if(vars)node.setAttribute('data-i18n-vars',JSON.stringify(vars));else node.removeAttribute('data-i18n-vars');
    node.textContent=t(key,vars);
  }
  function ready(fn){if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',fn);else fn();}
  function set(value,silent){
    value=norm(value)||'en';
    var changed=value!==current;current=value;root.lang=value;
    if(!silent){try{localStorage.setItem(KEY,value);}catch(e){}}
    ready(function(){apply(document);});
    if(changed&&!silent){
      var event;try{event=new CustomEvent('opx:langchange',{detail:{lang:value}});}catch(e){event=document.createEvent('CustomEvent');event.initCustomEvent('opx:langchange',false,false,{lang:value});}
      document.dispatchEvent(event);
    }
  }
  set(detect(),true);
  window.opxI18n={
    langs:LANGS,
    get:function(){return current;},
    /* BCP 47 tag for Intl / toLocaleString and the Accept-Language header. */
    locale:function(){return current==='zh-CN'?'zh-CN':'en-US';},
    set:function(value){set(value);},
    toggle:function(){set(current==='en'?'zh-CN':'en');},
    register:function(map){for(var name in map){var lang=norm(name);if(lang){dicts[lang]=dicts[lang]||{};merge(dicts[lang],map[name]);}}ready(function(){apply(document);});},
    t:t,has:has,apply:apply,mark:mark
  };
  document.addEventListener('click',function(event){var target=event.target.closest&&event.target.closest('[data-lang-toggle]');if(target){event.preventDefault();window.opxI18n.toggle();}});
  window.addEventListener('storage',function(event){if(event.key===KEY&&norm(event.newValue)&&norm(event.newValue)!==current)set(event.newValue);});
})();
