import { Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm';

@Injectable()
export class UsersService {

  constructor(
    @InjectRepository(User)
    private readonly userRepository:Repository<User>
  ){}

  async create(createUserDto: CreateUserDto) {
    const user = new User(createUserDto.email,createUserDto.password,createUserDto.username,createUserDto.role)
    return await this.userRepository.save(user);
  }

  async findOneByEmail(email: string){
    return await this.userRepository.findOneBy({email});
  }

  findAll() {
    return `This action returns all users`;
  }

  findOne() {
    return `This action returns all users`;
  }

  update(id: number, updateUserDto: UpdateUserDto) {
    return `This action updates a #${id} user`;
  }

  remove(id: number) {
    return `This action removes a #${id} user`;
  }
}
