import { IsEmail, IsNotEmpty, IsString, MinLength } from "class-validator";
import { Role } from "src/common/enum/role.enum";

export class RegisterDto{
    
    @IsString()
    @IsNotEmpty()
    readonly username:string;

    @IsString()
    @IsEmail()
    readonly email:string;

    @IsString()
    @MinLength(6)
    readonly password:string;

    readonly role:Role;
}