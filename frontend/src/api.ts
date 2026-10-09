let csrf = ''
export function setCsrf(value:string) {csrf=value}
export class ApiError extends Error {constructor(message:string,public status:number){super(message)}}
export async function api<T>(path:string, method='GET', body?:unknown):Promise<T>{
 const headers:Record<string,string>={}
 if(method!=='GET') headers['X-CSRF-Token']=csrf
 const form=body instanceof FormData
 if(body!==undefined&&!form) headers['Content-Type']='application/json'
 const response=await fetch('/api'+path,{method,credentials:'include',headers,body:body===undefined?undefined:form?body as FormData:JSON.stringify(body)})
 if(!response.ok){let message='Request failed';try{const data=await response.json();if(typeof data.detail==='string')message=data.detail}catch{}throw new ApiError(message,response.status)}
 return response.status===204?undefined as T:response.json()
}
export function snapshotPath(id:string){return '/snapshots/'+encodeURIComponent(id)}
export function errorText(error:unknown){return error instanceof Error?error.message:'Unexpected request failure'}
