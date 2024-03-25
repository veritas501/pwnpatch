import logging
import sys

__all__ = [
    'Log', 'log', 'use_style'
]

STYLE = {
    'fore': {  # 前景色
        'black': 30,  # 黑色
        'red': 31,  # 红色
        'green': 32,  # 绿色
        'yellow': 33,  # 黄色
        'blue': 34,  # 蓝色
        'purple': 35,  # 紫红色
        'cyan': 36,  # 青蓝色
        'white': 37,  # 白色
    },

    'back': {  # 背景
        'black': 40,  # 黑色
        'red': 41,  # 红色
        'green': 42,  # 绿色
        'yellow': 43,  # 黄色
        'blue': 44,  # 蓝色
        'purple': 45,  # 紫红色
        'cyan': 46,  # 青蓝色
        'white': 47,  # 白色
    },

    'mode': {  # 显示模式
        'normal': 0,  # 终端默认设置
        'bold': 1,  # 高亮显示
        'underline': 4,  # 使用下划线
        'blink': 5,  # 闪烁
        'invert': 7,  # 反白显示
        'hide': 8,  # 不可见
    },

    'default': {
        'end': 0,
    },
}


def use_style(string, mode='', fore='', back=''):
    if sys.stdout.isatty():
        style_list = [STYLE['mode'].get(mode), STYLE['fore'].get(fore),
                      STYLE['back'].get(back)]
        style_list = list(filter(lambda x: x is not None, style_list))
        if not style_list:
            style_list = [0]
        style = '\033[{}m'.format(';'.join(map(str, style_list)))
        end = '\033[{}m'.format(STYLE['default']['end'])
        return '{}{}{}'.format(style, string, end)
    else:
        return string


msg_prefixes = {
    'success': use_style('+', 'bold', 'green'),
    'failure': use_style('-', 'bold', 'red'),
    'debug': use_style('DEBUG', 'bold', 'red'),
    'info': use_style('*', 'bold', 'blue'),
    'warning': use_style('!', 'bold', 'yellow'),
    'error': use_style('ERROR', 'normal', 'red'),
}


class Log:
    def __init__(self, logger=None):
        if not logger:
            self.logger = logging.getLogger(__name__)
        else:
            self.logger = logger

    def _log(self, level, s):
        self.logger.log(level, s)

    def set_level(self, level):
        self.logger.setLevel(level)

    def get_level(self):
        return logging.getLevelName(self.logger.level)

    def success(self, s):
        self._log(logging.INFO, '[{}] {}'.format(msg_prefixes['success'], s))

    def failure(self, s):
        self._log(logging.INFO, '[{}] {}'.format(msg_prefixes['failure'], s))

    def fail(self, s):
        self.failure(s)

    def debug(self, s):
        self._log(logging.DEBUG, '[{}] {}'.format(msg_prefixes['debug'], s))

    def info(self, s):
        self._log(logging.INFO, '[{}] {}'.format(msg_prefixes['info'], s))

    def warning(self, s):
        self._log(logging.WARNING, '[{}] {}'.format(msg_prefixes['warning'], s))

    def warn(self, s):
        self.warning(s)

    def error(self, s):
        self._log(logging.ERROR, '[{}] {}'.format(msg_prefixes['error'], s))

    def underline(self, s):
        return use_style(s, 'underline')


logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)
log = Log()
