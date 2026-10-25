export type Row = Record<string, any>;
let token = sessionStorage.getItem('cloudpathx.session') || '';
export function setToken(value:string) {token=value; value?sessionStorage.setItem('cloudpathx.session',value):sessionStorage.removeItem('cloudpathx.session');}
export async function api(path:string,method='GET',body?:unknown):Promise<any> {
 const response=await fetch(`/api/v1${path}`,{method,headers:{...(token?{Authorization:`Bearer ${token}`} : {}),...(body!==undefined?{'Content-Type':'application/json'}:{})},body:body===undefined?undefined:JSON.stringify(body)});
 if(!response.ok){let message=`Request failed (${response.status})`;try{const data=await response.json();message=typeof data.detail==='string'?data.detail:JSON.stringify(data.detail||data);}catch{} throw new Error(message);}
 return response.status===204?null:response.json();
}
export async function download(format:string){const response=await fetch(`/api/v1/reports?format=${format}`,{headers:{Authorization:`Bearer ${token}`}});if(!response.ok)throw new Error('Report generation failed');const url=URL.createObjectURL(await response.blob());const anchor=document.createElement('a');anchor.href=url;anchor.download=`cloudpathx-report.${format}`;anchor.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
export function rows(data:any):Row[]{return Array.isArray(data)?data:data?.items||[];}
export const label=(value:unknown):string=>value===null||value===undefined?'—':typeof value==='object'?JSON.stringify(value):String(value);
