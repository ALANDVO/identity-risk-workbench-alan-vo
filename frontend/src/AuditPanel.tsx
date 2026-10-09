import {useEffect,useState} from 'react'
import {api,errorText} from './api'
import type {AuditEvent} from './types'
export function AuditPanel(){
 const [events,setEvents]=useState<AuditEvent[]>([]),[error,setError]=useState(''),[busy,setBusy]=useState(false)
 async function load(){setBusy(true);setError('');try{setEvents(await api<AuditEvent[]>('/audit?limit=100'))}catch(e){setError(errorText(e))}finally{setBusy(false)}}
 useEffect(()=>{void load()},[])
 return <section className="panel"><div className="section-top"><div><div className="eyebrow">Accountability</div><h2>Recent audit events</h2></div><button className="secondary" disabled={busy} onClick={()=>void load()}>Refresh audit</button></div><p>Latest 100 events, newest first. Server retains up to 5,000 operational events.</p>{error&&<p role="alert">{error}</p>}<div className="scroll-table"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Details</th></tr></thead><tbody>{events.map(e=><tr key={e.sequence}><td>{new Date(e.at).toLocaleString()}</td><td>{e.actor}</td><td>{e.action}</td><td><details><summary>Event {e.sequence}</summary><pre>{JSON.stringify(e.details,null,2)}</pre></details></td></tr>)}</tbody></table></div>{!events.length&&!busy&&<p>No audit events recorded.</p>}</section>
}
