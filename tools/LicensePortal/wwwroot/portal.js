'use strict';
const el=id=>document.getElementById(id);
let actor=null;
async function api(path,body){
  const options={credentials:'same-origin',cache:'no-store'};
  if(body!==undefined){options.method='POST';options.headers={'Content-Type':'application/json','X-GC-Portal':'1'};options.body=JSON.stringify(body)}
  const r=await fetch('/api/'+path,options);
  if(!r.ok){if(r.status===401)showSession(null);let msg='HTTP '+r.status;try{msg=(await r.json()).error||msg}catch{}throw Error(msg)}
  return await r.json();
}
function table(target,rows,action){
  const root=el(target);root.replaceChildren();
  if(!rows.length){root.textContent='No records';return;}
  const table=document.createElement('table'),header=table.createTHead().insertRow(),body=table.createTBody();
  for(const key of Object.keys(rows[0])){const th=document.createElement('th');th.textContent=key.replaceAll('_',' ');header.append(th);}
  if(action){const th=document.createElement('th');th.textContent='Actions';header.append(th);}
  for(const item of rows){const row=body.insertRow();for(const value of Object.values(item)){row.insertCell().textContent=value==null?'—':Array.isArray(value)?value.join(', '):String(value);}
    if(action)action(row.insertCell(),item);}
  root.append(table);
}
function button(label,handler){const b=document.createElement('button');b.type='button';b.textContent=label;b.onclick=async()=>{b.disabled=true;try{await handler();el('message').textContent='Operation completed';await refresh()}catch(e){el('message').textContent=String(e)}finally{b.disabled=false}};return b}
async function refresh(){
  table('customers',await api('customers'));table('subscriptions',await api('subscriptions'));
  table('invoices',await api('billing/invoices'),(cell,row)=>{
    if(actor.role!=='reviewer'||row.state!=='pending')return;
    const payment=document.createElement('input');payment.placeholder='Cleared payment reference';payment.maxLength=120;
    const amount=document.createElement('input');amount.type='number';amount.min='1';amount.max='1000000000000';amount.step='1';amount.placeholder='Confirmed minor units';
    cell.append(payment,amount,button('Confirm cleared payment',()=>{
      if(!payment.value||!amount.value||Number(amount.value)!==Number(row.amount_minor))throw Error('Confirm the exact cleared invoice amount and reference');
      return api('billing/invoices/'+row.id+'/decision',{decision:'paid',paymentReference:payment.value,paidMinor:Number(amount.value)});
    }),button('Void unpaid invoice',()=>api('billing/invoices/'+row.id+'/decision',{decision:'void',paymentReference:null,paidMinor:null})));
  });
  table('jobs',await api('jobs'),(cell,row)=>{
    if(row.completed_at){cell.append(button('Download result',async()=>{const data=await api('jobs/'+row.id+'/result');if(!data.envelope){el('message').textContent=row.kind==='rotate_authority'?'Signing authority rotated':'Subscription terms applied';return;}const url=URL.createObjectURL(new Blob([data.envelope],{type:'application/octet-stream'}));const a=document.createElement('a');a.href=url;a.download='gatewaycore-'+row.id+(row.kind==='revoke'?'.gcv':'.lic');a.click();URL.revokeObjectURL(url);}));return;}
    if(actor.role!=='reviewer')return;
    if(row.state==='pending')for(const choice of ['approved','rejected'])cell.append(button(choice,()=>api('jobs/'+row.id+'/decision',{decision:choice})));
    if(row.state==='approved')cell.append(button('Export approved job',async()=>{
      const job=await api('jobs/'+row.id+'/approved-package');const url=URL.createObjectURL(new Blob([JSON.stringify(job,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='approved-'+row.id+'.json';a.click();URL.revokeObjectURL(url);
    }));
  });
}
function form(id,handler){el(id).onsubmit=async event=>{event.preventDefault();const submit=event.submitter;submit.disabled=true;try{await handler(new FormData(event.target),submit);el('message').textContent='Saved';event.target.reset();await refresh()}catch(e){el('message').textContent=String(e)}finally{submit.disabled=false}};}
form('customer',f=>api('customers',{id:f.get('id'),name:f.get('name')}));
form('subscription',(f,submit)=>api(submit.value==='renew'?'subscriptions/'+encodeURIComponent(f.get('licenseId'))+'/renew':'subscriptions',{licenseId:f.get('licenseId'),customerId:f.get('customerId'),deploymentId:f.get('deploymentId'),edition:f.get('edition'),maxNodes:Number(f.get('maxNodes')),maxSites:Number(f.get('maxSites')),expiresAt:Math.floor(Date.parse(f.get('expiry')+'T00:00:00Z')/1000),features:f.get('features').split(',').map(x=>x.trim())}));
form('issue',async f=>{const file=f.get('request');if(!file||file.size>4096)throw Error('Invalid request size');await api('jobs',{kind:'issue',subscriptionId:f.get('subscriptionId'),siteId:f.get('siteId'),requestFile:await file.text(),allocationId:null})});
form('revoke',f=>api('jobs',{kind:'revoke',subscriptionId:f.get('subscriptionId'),allocationId:f.get('allocationId'),siteId:null,requestFile:null}));
form('rotation',f=>api('subscriptions/'+encodeURIComponent(f.get('subscriptionId'))+'/rotate-authority',{newKeyId:f.get('newKeyId'),newPublicKey:f.get('newPublicKey'),customerTrustStaged:f.get('customerTrustStaged')==='on'}));
form('invoice',f=>api('billing/invoices',{subscriptionId:f.get('subscriptionId'),renewalJobId:f.get('renewalJobId')||null,currency:f.get('currency'),amountMinor:Number(f.get('amountMinor'))}));
function showSession(info){
  actor=info?.authenticated?info:null;
  el('identity').textContent=actor?actor.id+' · '+actor.role:'Certificate verified · password required';
  el('signin').hidden=!!actor;el('logout').hidden=!actor;
  el('records').hidden=!actor;el('requester').hidden=!actor||actor.role!=='requester';
  if(!actor)for(const id of ['customers','subscriptions','jobs','invoices'])el(id).replaceChildren();
}
el('login').onsubmit=async event=>{
  event.preventDefault();const submit=event.submitter;submit.disabled=true;
  try{const result=await api('session/login',{password:new FormData(event.target).get('password')});
    showSession(result);el('message').textContent='Signed in';await refresh()}
  catch(e){el('message').textContent=String(e)}finally{event.target.reset();submit.disabled=false}
};
el('logout').onclick=async()=>{try{await api('session/logout',{});showSession(null);el('message').textContent='Signed out'}catch(e){el('message').textContent=String(e)}};
(async()=>{showSession(await api('session'));if(actor)await refresh()})().catch(e=>el('message').textContent=String(e));
