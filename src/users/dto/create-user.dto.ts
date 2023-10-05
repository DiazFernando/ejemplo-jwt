import { Role } from "src/common/enum/role.enum";

export class CreateUserDto {
    readonly email:string;
    readonly password:string;
    readonly username?:string;
    readonly role?:Role;
}
