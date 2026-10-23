// Ошибка входных данных: её текст безопасно показывать пользователю.
export class FormatError extends Error {
  constructor(message) {
    super(message);
    this.name = 'FormatError';
  }
}
