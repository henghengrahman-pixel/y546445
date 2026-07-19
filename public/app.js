'use strict';
for (const el of document.querySelectorAll('[data-confirm]')) el.addEventListener('click',e=>{if(!confirm(el.dataset.confirm))e.preventDefault();});
let remaining=60*60; setInterval(()=>{remaining--; if(remaining===300&&!document.hidden) alert('Sesi akan logout otomatis dalam 5 menit jika tidak ada aktivitas.');},1000);
['click','keydown','mousemove','touchstart'].forEach(ev=>addEventListener(ev,()=>remaining=60*60,{passive:true}));
window.openModal=function(id){const el=document.getElementById(id);if(el){el.classList.add('show');document.body.style.overflow='hidden';}};
window.closeModal=function(id){const el=document.getElementById(id);if(el){el.classList.remove('show');document.body.style.overflow='';}};
document.addEventListener('click',e=>{if(e.target.classList&&e.target.classList.contains('modal')){e.target.classList.remove('show');document.body.style.overflow='';}});
document.addEventListener('keydown',e=>{if(e.key==='Escape')document.querySelectorAll('.modal.show').forEach(x=>x.classList.remove('show'));});
