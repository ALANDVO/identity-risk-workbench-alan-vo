import type {Policy} from './types'
export function PolicyEditor({policy,onChange}:{policy:Policy;onChange:(p:Policy)=>void}){
 return <details className="policy"><summary>Analysis policy · customize before importing</summary><div className="grid">
 <label>Stale after days<input type="number" min="1" max="3650" value={policy.stale_days} onChange={e=>onChange({...policy,stale_days:Number(e.target.value)})}/></label>
 <label>Never-used grace days<input type="number" min="1" max="3650" value={policy.never_used_grace_days} onChange={e=>onChange({...policy,never_used_grace_days:Number(e.target.value)})}/></label>
 <label>Concentration share<input type="number" min="0.01" max="1" step="0.05" value={policy.concentration_threshold} onChange={e=>onChange({...policy,concentration_threshold:Number(e.target.value)})}/></label>
 <label>Minimum enabled population<input type="number" min="1" max="3650" value={policy.minimum_population} onChange={e=>onChange({...policy,minimum_population:Number(e.target.value)})}/></label></div>
 <label>Privileged permission requirements · one per line<textarea value={policy.privileged_permissions.join('\n')} onChange={e=>onChange({...policy,privileged_permissions:e.target.value.split('\n').filter(Boolean)})}/></label>
 <p>Wildcard grants cover a whole service or action segment. Deny rules, conditions, and resource scopes are not modeled.</p>
 <h3>Conflicting duties</h3>{policy.toxic_pairs.map((pair,i)=><div className="rule-row" key={i}>
 <label>Rule name<input value={pair.name} onChange={e=>onChange({...policy,toxic_pairs:policy.toxic_pairs.map((p,j)=>j===i?{...p,name:e.target.value}:p)})}/></label>
 <label>First permission<input value={pair.left} onChange={e=>onChange({...policy,toxic_pairs:policy.toxic_pairs.map((p,j)=>j===i?{...p,left:e.target.value}:p)})}/></label>
 <label>Second permission<input value={pair.right} onChange={e=>onChange({...policy,toxic_pairs:policy.toxic_pairs.map((p,j)=>j===i?{...p,right:e.target.value}:p)})}/></label>
 <button type="button" className="quiet" onClick={()=>onChange({...policy,toxic_pairs:policy.toxic_pairs.filter((_,j)=>j!==i)})}>Remove rule {i+1}</button></div>)}
 <button type="button" className="quiet" disabled={policy.toxic_pairs.length>=30} onClick={()=>onChange({...policy,toxic_pairs:[...policy.toxic_pairs,{name:'New conflict',left:'service:create',right:'service:approve'}]})}>Add conflict rule</button>
 </details>
}
