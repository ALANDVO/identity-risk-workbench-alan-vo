import {useEffect,useState} from 'react'
import {api,errorText} from './api'
import type {Analysis,Policy,Snapshot} from './types'
import {PolicyEditor} from './PolicyEditor'
export function ImportPanel({onImported}:{onImported:(s:Snapshot)=>void}){
 const [file,setFile]=useState<File|null>(null),[name,setName]=useState(''),[policy,setPolicy]=useState<Policy|null>(null),[preview,setPreview]=useState<Analysis|null>(null),[busy,setBusy]=useState(false),[message,setMessage]=useState('')
 useEffect(()=>{let active=true;api<Policy>('/policy').then(p=>{if(active)setPolicy(p)}).catch(e=>{if(active)setMessage(errorText(e))});return()=>{active=false}},[])
 function changePolicy(value:Policy){setPolicy(value);setPreview(null)}
 async function run(commit:boolean){if(!file||!policy)return;setBusy(true);setMessage('');try{
 const form=new FormData();form.append('file',file);form.append('policy',JSON.stringify(policy));form.append('name',name)
 if(commit){const result=await api<{snapshot:Snapshot;replayed:boolean}>('/snapshots','POST',form);setMessage(result.replayed?'This exact export was already imported. Opened the existing evidence.':'Snapshot imported.');onImported(result.snapshot)}
 else {setPreview(null);setPreview(await api<Analysis>('/import/preview','POST',form))}
 }catch(e){setPreview(null);setMessage(errorText(e))}finally{setBusy(false)}}
 return <section className="panel"><div className="eyebrow">Evidence intake</div><h2>Import an identity export</h2><p>JSON snapshots only, up to 5 MiB. Preview validates references, timestamps, cycles, and policy before saving any identity data.</p>
 <fieldset disabled={busy}><div className="grid"><label>Snapshot name<input value={name} maxLength={160} onChange={e=>setName(e.target.value)} placeholder="Production · October review"/></label>
 <label>Identity export<input type="file" accept=".json,application/json" onChange={e=>{setFile(e.target.files?.[0]??null);setPreview(null);setMessage('')}}/></label></div>
 {policy&&<PolicyEditor policy={policy} onChange={changePolicy}/>}
 <div className="actions"><button onClick={()=>void run(false)} disabled={!file||!policy}>{busy?'Working…':'Preview import'}</button><button className="secondary" onClick={()=>void run(true)} disabled={!preview||!name.trim()}>Save snapshot</button><a href="/examples/identity-export.json" download>Download synthetic example</a></div></fieldset>
 {message&&<p role="status">{message}</p>}{preview&&<div className="notice success" role="status"><strong>Valid export:</strong> {preview.summary.identities} identities, {preview.summary.enabled} enabled, {preview.summary.findings} findings. Nothing has been stored yet.</div>}
 </section>
}
