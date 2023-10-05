import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Req } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { AuthGuard } from './auth.guard';
import { request } from 'http';
import { Role } from 'src/common/enum/role.enum';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  register(@Body() registerDto:RegisterDto) {
    return this.authService.register(registerDto);
  }

  @Post('login')
  login(@Body() loginDto:LoginDto) {
    return this.authService.login(loginDto);
  }

  @Get('home')
  @UseGuards(AuthGuard)
  getHome(@Req() request) {
    if(request.user.role !== Role.ADMIN)
      return "no tiene suficiente permisos para acceder a mas informacion";
    if(request.user.role === Role.ADMIN)
      return request.user;
    return "No deberias poder ver esto";
  }


}
