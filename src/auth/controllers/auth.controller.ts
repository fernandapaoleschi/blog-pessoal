import { Body, Controller, HttpCode, HttpStatus, Post, UseGuards } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";
import { AuthService } from "../services/auth.service";
import { UsuarioLogin } from "../entities/usuariologin.entity";

@Controller("/auth")
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post("/logar")
  @UseGuards(AuthGuard("local"))
  @HttpCode(HttpStatus.OK)
  login(@Body() usuarioLogin: UsuarioLogin) {
    return this.authService.login(usuarioLogin);
  }
}
