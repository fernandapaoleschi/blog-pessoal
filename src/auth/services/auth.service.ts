import { HttpException, HttpStatus, Injectable } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { UsuarioService } from "../../usuario/services/usuario.service";
import { Bcrypt } from "../bcrypt/bcrypt";
import { UsuarioLogin } from "../entities/usuariologin.entity";

@Injectable()
export class AuthService {
  constructor(
    private usuarioService: UsuarioService,
    private jwtService: JwtService,
    private bcrypt: Bcrypt
  ) {}

  async validateUser(usuario: string, senha: string): Promise<any> {
    const buscaUsuario = await this.usuarioService.findByUsuario(usuario);

    // aqui é melhor retornar null (pra strategy lançar 401)
    if (!buscaUsuario) return null;

    const matchPassword = await this.bcrypt.compararSenhas(
      senha,
      buscaUsuario.senha
    );

    if (!matchPassword) return null;

    // remove senha do retorno
    const { senha: _, ...resposta } = buscaUsuario;
    return resposta;
  }

  async login(usuarioLogin: UsuarioLogin) {
    const buscaUsuario = await this.usuarioService.findByUsuario(
      usuarioLogin.usuario
    );

    if (!buscaUsuario)
      throw new HttpException("Usuário não encontrado!", HttpStatus.NOT_FOUND);

    const payload = { sub: buscaUsuario.usuario };

    return {
      id: buscaUsuario.id,
      nome: buscaUsuario.nome,
      usuario: buscaUsuario.usuario,
      senha: "",
      foto: buscaUsuario.foto,
      token: `Bearer ${this.jwtService.sign(payload)}`,
    };
  }
}
