import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from 'src/users/users.service';
import { RegisterDto } from './dto/register.dto';
import { User } from 'src/users/entities/user.entity';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';


@Injectable()
export class AuthService {
  constructor(private userService:UsersService,
              private jwtService:JwtService){}

  async register(registerDto:RegisterDto){
    
    const user = await this.userService.findOneByEmail(registerDto.email)
    
    if(user){
      throw new BadRequestException('El usuario ya existe')
    }
    const  pass_encriptada = await bcrypt.hash(registerDto.password,10)
    return await this.userService.create(new User(registerDto.email,pass_encriptada,registerDto.username))
  }

  async login({email,password}:LoginDto){
    const user= await this.userService.findOneByEmail(email);
    if(!user)
      throw new UnauthorizedException('Usuario incorrecto');

    const isPasswordValid = await bcrypt.compare(password,user.password);
    if(!isPasswordValid)
      throw new UnauthorizedException('Password incorrecto');

    const payload = {email: user.email}

    const token = await this.jwtService.signAsync(payload);

    return token
  }
  
}
