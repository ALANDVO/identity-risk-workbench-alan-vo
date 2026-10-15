import {describe,it,expect,vi} from 'vitest'
import {render,screen,waitFor} from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {ImportPanel} from './ImportPanel'
import {FindingReview} from './FindingReview'
import {PlanPanel} from './PlanPanel'
import {SnapshotView} from './SnapshotView'
import {api,ApiError,setCsrf} from './api'
import type {Policy,Finding,Identity,Detail} from './types'
const policy:Policy={stale_days:90,never_used_grace_days:30,concentration_threshold:.5,minimum_population:3,privileged_permissions:['identity:*'],toxic_pairs:[]}
const finding:Finding={id:'f1',identity_id:'u1',rule:'stale',severity:'medium',points:20,title:'No recent sign-in',evidence:{days:100},recommendation:'Check activity before disabling.'}
const identity:Identity={id:'u1',display_name:'Test account',kind:'human',enabled:true,owner:null,mfa:true,direct_roles:['reader'],groups:[],effective_roles:['reader'],permissions:['x:read'],paths:{reader:['identity:u1','role:reader']},risk_score:20,finding_count:1,grant_share:1,privileged:false,last_login:null}
const secondIdentity:Identity={...identity,id:'svc1',display_name:'Service bot',kind:'service',risk_score:25}
const secondFinding:Finding={id:'f2',identity_id:'svc1',rule:'orphan_service',severity:'high',points:25,title:'Service identity has no accountable owner',evidence:{owner:null},recommendation:'Assign owner.'}
function response(data:unknown,status=200){return new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json'}})}
describe('evidence workflow',()=>{
 it('requires a successful preview and invalidates it when policy changes',async()=>{
  const fetch=vi.spyOn(globalThis,'fetch').mockImplementation(async (_url,init)=>response(init?.method==='POST'?{summary:{identities:1,enabled:1,findings:1}}:policy))
  render(<ImportPanel onImported={()=>{}}/>);const user=userEvent.setup()
  await screen.findByText('Analysis policy · customize before importing')
  await user.type(screen.getByLabelText('Snapshot name'),'Evidence')
  expect(screen.getByRole('button',{name:'Save snapshot'})).toBeDisabled()
  await user.upload(screen.getByLabelText('Identity export'),new File(['{}'],'export.json',{type:'application/json'}))
  await user.click(screen.getByRole('button',{name:'Preview import'}))
  await screen.findByText(/Valid export:/)
  expect(screen.getByRole('button',{name:'Save snapshot'})).toBeEnabled()
  await user.click(screen.getByText('Analysis policy · customize before importing'))
  await user.clear(screen.getByLabelText('Stale after days'));await user.type(screen.getByLabelText('Stale after days'),'120')
  expect(screen.getByRole('button',{name:'Save snapshot'})).toBeDisabled();expect(fetch).toHaveBeenCalledTimes(2)
 })
 it('shows a review conflict without claiming the save succeeded',async()=>{
  vi.spyOn(globalThis,'fetch').mockResolvedValue(response({detail:'Review changed; refresh before saving'},409))
  const saved=vi.fn();render(<FindingReview finding={finding} snapshotId="s1" canReview onSaved={saved}/>);const user=userEvent.setup()
  await user.click(screen.getByText('Review this finding'));await user.type(screen.getByLabelText('Review note'),'Owner confirmed')
  await user.click(screen.getByRole('button',{name:'Save review'}))
  expect(await screen.findByRole('alert')).toHaveTextContent('Review changed');expect(saved).not.toHaveBeenCalled()
 })
 it('sends only a direct-grant action and requires preview before saving a plan',async()=>{
  const fetch=vi.spyOn(globalThis,'fetch').mockResolvedValue(response({resolved:[finding],introduced:[],remaining:[],affected:[],notice:'Simulation only.'}))
  render(<PlanPanel snapshotId="s1" identities={[identity]} plans={[]} user={{subject:'a',username:'A',roles:['reviewer'],csrf_token:'test'}} onSaved={async()=>{}}/>);const user=userEvent.setup()
  await user.type(screen.getByLabelText('Plan title'),'Reduce access');await user.selectOptions(screen.getByLabelText('Direct grant'),'reader');await user.click(screen.getByRole('button',{name:'Add action'}))
  expect(screen.getByRole('button',{name:'Save proposed plan'})).toBeDisabled()
  await user.click(screen.getByRole('button',{name:'Preview plan'}));await screen.findByText('1 resolved')
  expect(screen.getByRole('button',{name:'Save proposed plan'})).toBeEnabled()
  const body=JSON.parse(fetch.mock.calls[0][1]?.body as string);expect(body).toEqual({actions:[{identity_id:'u1',kind:'remove_role',value:'reader'}]})
  await user.click(screen.getByRole('button',{name:'Remove action 1'}));expect(screen.getByRole('button',{name:'Save proposed plan'})).toBeDisabled()
 })
 it('filters identities and findings by triggered rule in SnapshotView',async()=>{
  const detail:Detail={snapshot:{id:'s1',name:'Oct Snapshot',digest:'abc',observed_at:'2026-10-01T00:00:00Z',imported_at:'2026-10-01T00:00:00Z',imported_by:'admin',version:1,summary:{identities:2,enabled:2,privileged:0,findings:2,by_severity:{medium:1,high:1},by_rule:{stale:1,orphan_service:1},effective_permission_grants:2}},analysis:{summary:{identities:2,enabled:2,privileged:0,findings:2,by_severity:{medium:1,high:1},by_rule:{stale:1,orphan_service:1},effective_permission_grants:2},identities:[identity,secondIdentity],findings:[finding,secondFinding],policy,limitations:[],snapshot_digest:'abc',observed_at:'2026-10-01T00:00:00Z'},reviews:[],plans:[]}
  render(<SnapshotView detail={detail} user={{subject:'a',username:'A',roles:['reviewer'],csrf_token:'test'}} onSaved={async()=>{}} onDeleted={async()=>{}}/>);const user=userEvent.setup()
  expect(screen.getByRole('button',{name:/Test account/})).toBeInTheDocument()
  expect(screen.getByRole('button',{name:/Service bot/})).toBeInTheDocument()
  await user.selectOptions(screen.getByLabelText('Filter by finding rule'),'orphan_service')
  expect(screen.queryByRole('button',{name:/Test account/})).not.toBeInTheDocument()
  expect(screen.getByRole('heading',{name:'Service identity has no accountable owner'})).toBeInTheDocument()
 })
 it('attaches csrf to mutations and preserves error status',async()=>{
  const fetch=vi.spyOn(globalThis,'fetch').mockResolvedValue(response({detail:'Forbidden'},403));setCsrf('csrf-example')
  await expect(api('/anything','POST',{})).rejects.toBeInstanceOf(ApiError)
  expect(fetch.mock.calls[0][1]?.headers).toEqual({'X-CSRF-Token':'csrf-example','Content-Type':'application/json'})
 })
})
