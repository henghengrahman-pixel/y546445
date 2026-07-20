'use strict';
for (const el of document.querySelectorAll('[data-confirm]')) el.addEventListener('click',e=>{if(!confirm(el.dataset.confirm))e.preventDefault();});
let remaining=60*60; setInterval(()=>{remaining--; if(remaining===300&&!document.hidden) alert('Sesi akan logout otomatis dalam 5 menit jika tidak ada aktivitas.');},1000);
['click','keydown','mousemove','touchstart'].forEach(ev=>addEventListener(ev,()=>remaining=60*60,{passive:true}));
window.openModal=function(id){const el=document.getElementById(id);if(el){el.classList.add('show');document.body.style.overflow='hidden';}};
window.closeModal=function(id){const el=document.getElementById(id);if(el){el.classList.remove('show');document.body.style.overflow='';}};
document.addEventListener('click',e=>{if(e.target.classList&&e.target.classList.contains('modal')){e.target.classList.remove('show');document.body.style.overflow='';}});
document.addEventListener('keydown',e=>{if(e.key==='Escape')document.querySelectorAll('.modal.show').forEach(x=>x.classList.remove('show'));});

function bindStaffPicker(searchId,selectId,summaryId){
 const search=document.getElementById(searchId),select=document.getElementById(selectId),box=document.getElementById(summaryId); if(!select||!box)return;
 const options=[...select.options].slice(1);
 if(search)search.addEventListener('input',()=>{const q=search.value.trim().toLowerCase();for(const o of options)o.hidden=q&&!o.dataset.label.includes(q);});
 select.addEventListener('change',async()=>{if(!select.value){box.textContent='Pilih staf untuk melihat riwayat.';return;}box.innerHTML='Memuat data staf...';try{const r=await fetch('/api/staff/'+select.value+'/summary');const x=await r.json();box.innerHTML=`<div class="summary-grid"><span><b>Lama kerja</b>${x.work_duration}</span><span><b>Group / Jabatan</b>${x.group_name} / ${x.position}</span><span><b>Riwayat SP</b>${x.warning_count} kali${x.last_warning?' • '+x.last_warning:''}</span><span><b>Terakhir cuti</b>${x.last_leave_end||'Belum ada'}</span><span><b>History cashbon</b>${x.cashbon_count} transaksi • Rp ${Number(x.cashbon_total).toLocaleString('id-ID')}</span><span><b>Cashbon belum lunas</b>Rp ${Number(x.cashbon_active_total).toLocaleString('id-ID')}</span></div>`;}catch(e){box.textContent='Gagal memuat data staf.';}});
}
bindStaffPicker('cashbonStaffSearch','cashbonStaff','cashbonStaffSummary');
bindStaffPicker('leaveStaffSearch','leaveStaff','leaveStaffSummary');
