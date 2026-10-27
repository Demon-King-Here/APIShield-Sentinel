from fastapi import APIRouter,Request,Response,HTTPException
from app.security.authentication import Credentials,Setup,PasswordChange,set_cookie,clear_cookie

router=APIRouter(prefix='/api/auth')


def response_for(token,request):
    response=Response(status_code=204)
    set_cookie(response,token,request)
    return response


@router.post('/setup')
async def setup(data:Setup,request:Request):
    token=await request.app.state.runtime.auth.create_account(data,request)
    return response_for(token,request)


@router.post('/login')
async def login(data:Credentials,request:Request):
    runtime=request.app.state.runtime
    token=await runtime.auth.login(data,request)
    # Rotate any existing cookie session to prevent fixation and accumulation.
    if request.state.session_token:
        runtime.auth.revoke(request.state.session_token)
    return response_for(token,request)


@router.post('/logout')
async def logout(request:Request):
    runtime=request.app.state.runtime
    if request.state.session_token:
        runtime.auth.revoke(request.state.session_token)
    runtime.db.audit('admin_logout','Administrator signed out')
    response=Response(status_code=204)
    clear_cookie(response)
    return response


@router.post('/password')
async def change_password(data:PasswordChange,request:Request):
    if not request.state.admin_session:
        raise HTTPException(401,'Sign in with your administrator password first')
    await request.app.state.runtime.auth.change_password(data,request)
    response=Response(status_code=204)
    clear_cookie(response)
    return response
