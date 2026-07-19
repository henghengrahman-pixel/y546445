'use strict';
for (const el of document.querySelectorAll('[data-confirm]')) el.addEventListener('click',e=>{if(!confirm(el.dataset.confirm))e.preventDefault();});
let remaining=60*60; setInterval(()=>{remaining--; if(remaining===300&&!document.hidden) alert('Sesi akan logout otomatis dalam 5 menit jika tidak ada aktivitas.');},1000);
['click','keydown','mousemove','touchstart'].forEach(ev=>addEventListener(ev,()=>remaining=60*60,{passive:true}));
