import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from 'src/users/users.module';
import { UsersService } from 'src/users/users.service';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports:[
    JwtModule.register({
      global: true,
      secret: "LA PALABRA SECRETA O EL SECRETO ES UNA PALABRA SECRETAMENTE SECRETA, Y UN BREAK",
      signOptions: {expiresIn:"1d"}
    }),
    UsersModule],
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule {}
