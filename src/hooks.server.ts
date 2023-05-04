import { sequence } from '@sveltejs/kit/hooks';
import { dbConn } from './dbConn';
import { findUserByUrl } from './backendUtils';
import { SECRET_KEY,SECRET_ACCESS,SECRET_COMM } from '$env/static/private';
import jwt from 'jsonwebtoken';

async function firstHandle({ event, resolve }) {
    //console.log('first handle');
    //event.locals = "I went through the first load!"
    const authToken = event.cookies.get('authToken');
    //console.log("authtoken hook",authToken)
    try{
        if(!authToken) event.locals.authedUser = undefined;

        const claims = jwt.verify(authToken,SECRET_ACCESS);
        if(!claims) event.locals.authedUser = undefined;

        if(authToken && claims){
            const collection = await dbConn();
            const fullUser = await findUserByUrl(collection,claims.authedUser.URL);
            const {password,...userMinusPassword} = fullUser;
            event.locals.authedUser = userMinusPassword;

        }
    }
    finally{
        const response = await resolve(event);
        return response;
    }
}

async function secondHandle({ event, resolve }) {
    //console.log('second handle');
    //console.log(event.locals);
    if(!event.locals.authedUser){
        const refreshToken = event.cookies.get('refreshToken');
        //console.log(refreshToken);
        try{
            if(!refreshToken) event.locals.authedUser = undefined;
    
            if(refreshToken){

                //since we are refreshing we sign the refresh token with the SECRET_COMM to verify comms ONLY, refresh server will verify token signing new auth token if successful
                const commToken = jwt.sign({authedUser:refreshToken},SECRET_COMM,{expiresIn:30});

                const response = await fetch('https://cn-refresh.vercel.app/api/refresh',{method:"POST", credentials: 'include',headers:{'ACCESS-CONTROL-COMM-TOKEN':commToken,'ACCESS-CONTROL-REFRESH-TOKEN':refreshToken}});
                //console.log(response);
                const responseHeaders = response.headers.get('set-cookie');

                const responseCookies = {};

                if(responseHeaders){
                    responseHeaders.split(",").forEach(cookieString => {
                        const cookieAttrs = cookieString.trim().split(";");
                        const [name, value] = cookieAttrs[0].split("=");
                        responseCookies[name] = value;
                      });
                        //console.log(responseCookies);
                }

                //console.log(responseCookies);

                event.cookies.set('authToken',responseCookies.authToken,{httpOnly: true,maxAge:60 * 60 * 24,sameSite: 'strict'});

                const authedUserClaim = jwt.verify(responseCookies.authToken,SECRET_ACCESS);

                //console.log(authedUserClaim)
                if(authedUserClaim)event.locals.authedUser = authedUserClaim.authedUser
    
            }
        }
        finally{
            const response = await resolve(event);
            return response;
        }

    }
    if(event.locals){
        const response = await resolve(event);
        return response;
    }

}

export const handle = sequence(firstHandle, secondHandle);