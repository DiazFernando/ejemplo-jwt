import { Role } from "src/common/enum/role.enum";
import { Column, Entity, PrimaryGeneratedColumn } from "typeorm";

@Entity()
export class User {

    @PrimaryGeneratedColumn()
    id:number;
    
    @Column({unique:true , nullable:false})
    username:string;

    @Column({unique:true , nullable:false})
    email:string;

    @Column({nullable:false})
    password:string;

    @Column({type:'enum', default:Role.USER, enum:Role})
    role:Role;

    constructor(email:string,password:string,username:string,role?:Role){
        this.email= email;
        this.password=password;
        this.username = username;
        this.role = role;
    }
}
