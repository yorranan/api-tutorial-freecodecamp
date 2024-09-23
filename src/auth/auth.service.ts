import { ForbiddenException, Injectable, Post } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDTO } from './dto/auth.dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
@Injectable({})
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signup(dto: AuthDTO) {

    const hash = await argon.hash(dto.password);
    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
        select: {
          id: true,
          email: true,
          createdAt: true,
        },
      });
      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credetials taken');
        }
      }
    }

  }

  async signin(dto: AuthDTO) {
    const user = await this.prisma.user.findUnique({
        where: {
            email: dto.email,
        }
    })
    if (!user) {
        throw new ForbiddenException('Credentials Incorrect!')
    }
    const pwMatches = await argon.verify(user.hash, dto.password);
    if(!pwMatches){
        throw new ForbiddenException('Credentials Incorrect!')
    }

    delete user.hash
    return user
  }
}
