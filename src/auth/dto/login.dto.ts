import { IsEmail, IsNotEmpty, IsString, MinLength } from "class-validator";

export class LoginDto{

    @IsEmail()
    readonly email:string;
    
    @IsString()
    readonly password:string;
}