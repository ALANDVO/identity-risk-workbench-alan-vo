import {describe,it,expect,vi} from 'vitest'
import {render,screen,waitFor} from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {ImportPanel} from './ImportPanel'
import {FindingReview} from './FindingReview'
import {PlanPanel} from './PlanPanel'
import {api,ApiError,setCsrf} from './api'
import type {Policy,Finding,Identity} from './types'
const policy:Policy={stale_days:90,never_used_grace_days:30,concentration_threshold:.5,minimum_population:3,privileged_permissions:['identity:*'],toxic_pairs:[]}
const finding:Finding={id:'f1',identity_id:'u1',rule:'stale',severity:'medium',points:20,title:'No recent sign-in',evidence:{days:100},recommendation:'Check activity before disabling.'}
const identity:Identity={id:'u1',display_name:'Test account',kind:'human',enabled:true,owner:null,mfa:true,direct_roles:['reader'],groups:[],effective_roles:['reader'],permissions:['x:read'],paths:{reader:['identity:u1','role:reader']},risk_score:20,finding_count:1,grant_share:1,privileged:false,last_login:null}
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
 it('attaches csrf to mutations and preserves error status',async()=>{
  const fetch=vi.spyOn(globalThis,'fetch').mockResolvedValue(response({detail:'Forbidden'},403));setCsrf('csrf-example')
  await expect(api('/anything','POST',{})).rejects.toBeInstanceOf(ApiError)
  expect(fetch.mock.calls[0][1]?.headers).toEqual({'X-CSRF-Token':'csrf-example','Content-Type':'application/json'})
 })
})
