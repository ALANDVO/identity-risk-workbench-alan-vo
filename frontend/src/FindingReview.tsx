import {useState} from 'react'
import type {Finding,Review} from './types'
import {api,errorText,snapshotPath} from './api'
export function FindingReview({finding,review,snapshotId,canReview,onSaved}:{finding:Finding;review?:Review;snapshotId:string;canReview:boolean;onSaved:()=>Promise<void>}){
 const [decision,setDecision]=useState(review?.decision??'open'),[note,setNote]=useState(review?.note??''),[busy,setBusy]=useState(false),[error,setError]=useState('')
 async function save(){setBusy(true);setError('');try{await api(snapshotPath(snapshotId)+'/reviews/'+encodeURIComponent(finding.id),'POST',{decision,note,version:review?.version??0});await onSaved()}catch(e){setError(errorText(e))}finally{setBusy(false)}}
 return <article className="finding"><div className="finding-heading"><span className={'badge '+finding.severity}>{finding.severity}</span><h3>{finding.title}</h3><span className="muted">+{finding.points} points</span></div><p>{finding.recommendation}</p>
 <details><summary>Evidence and grant paths</summary><pre>{JSON.stringify(finding.evidence,null,2)}</pre></details>
 {review&&<p className="muted">Recorded decision: {review.decision} · {review.author} · revision {review.version}</p>}
 {canReview&&<details><summary>Review this finding</summary><fieldset disabled={busy}><div className="grid"><label>Finding decision<select aria-label="Finding decision" value={decision} onChange={e=>setDecision(e.target.value)}><option value="open">Open</option><option value="accepted">Accept risk</option><option value="false_positive">False positive</option><option value="remediated">Reported remediated</option></select></label><label>Review note<textarea value={note} maxLength={4000} onChange={e=>setNote(e.target.value)}/></label></div><button disabled={!note.trim()} onClick={()=>void save()}>{busy?'Saving…':'Save review'}</button></fieldset><p className="muted">Decisions annotate historical evidence. Remediation is not independently verified by this app.</p></details>}
 {error&&<p role="alert" className="error">{error}</p>}</article>
}
