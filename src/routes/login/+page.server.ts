import type {Actions,RequestEvent,ActionFailure, Redirect} from '@sveltejs/kit';
import { redirect } from '@sveltejs/kit';
import type {loginFormResponse} from '../../types/form';
import { findUserByEmailWithPassword } from "../../backendUtils";
import { dbConn } from '../../dbConn';
import { SECRET_COMM } from '$env/static/private';
import bcryptjs from 'bcryptjs';
import jwt from 'jsonwebtoken';


export async function load({cookies}){
    const authToken =  cookies.get('authToken');

    if(!authToken)return{clearUser:true}

    return {clearUser: false}

}

export const actions:Actions = {
    login: async({cookies,request,fetch}:RequestEvent): Promise<loginFormResponse|ActionFailure<loginFormResponse> | Redirect> =>{

        const loginFormData = await request.formData();
        const email = loginFormData.get('email')?.toString()??'';
        const password = loginFormData.get('password')?.toString()??'';

        let loginResponse={
            email,
            error: false,
            message: '',
        }

        try{
            const collection = await dbConn();
            const userAttemptingLogin = await findUserByEmailWithPassword(collection,email);
            const authAttempt = await bcryptjs.compare(password,userAttemptingLogin.password);
            if(!authAttempt){
                loginResponse.error = true,
                loginResponse.message = "Invalid Username or Password!"
            }
            if(authAttempt){
                const {password,...userAttemptingLoginMinusPassword} = userAttemptingLogin;
                const commToken = jwt.sign({authedUser:userAttemptingLoginMinusPassword},SECRET_COMM,{expiresIn:30});

                cookies.set('commToken',commToken,{httpOnly: true,maxAge:60 * 60 * 24,sameSite: 'strict'});

                const response = await fetch('https://cn-refresh.vercel.app/api/login',{method:"POST", credentials: 'include',headers:{'ACCESS-CONTROL-COMM-TOKEN':commToken}});

                //console.log("response ",response);
                //const data = await response.json();
                //console.log("data ",data);

                const responseHeaders = response.headers.get('set-cookie');
                const responseCookies: { [key: string]: string }  = {};

                if(responseHeaders){
                    responseHeaders.split(",").forEach(cookieString => {
                        const cookieAttrs = cookieString.trim().split(";");
                        const [name, value] = cookieAttrs[0].split("=");
                        responseCookies[name] = value;
                      });
                        console.log(responseCookies);
                }

                cookies.set('authToken',responseCookies.authToken,{httpOnly: true,maxAge:60 * 60 * 24,sameSite: 'strict'});

                cookies.set('refreshToken',responseCookies.refreshToken,{httpOnly: true,maxAge:60 * 60 * 24 * 120,sameSite: 'strict'});
                
                throw redirect(302,`/`)
            }
        }
        finally{
        }

        return loginResponse
        
    },

}