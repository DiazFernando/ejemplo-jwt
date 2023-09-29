import { BadRequestException, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from 'src/users/users.service';
import { RegisterDto } from './dto/register.dto';
import { User } from 'src/users/entities/user.entity';
import * as bcrypt from 'bcrypt';


@Injectable()
export class AuthService {
  constructor(private userService:UsersService,
              /*private jwtService:JwtService*/){}

  async register(registerDto:RegisterDto){
    
    const user = await this.userService.findOneByEmail(registerDto.email)
    
    if(user){
      throw new BadRequestException('El usuario ya existe')
    }
    const  pass_encriptada = await bcrypt.hash(registerDto.password,10)
    return await this.userService.create(new User(registerDto.email,pass_encriptada,registerDto.username))
  }
  
}
