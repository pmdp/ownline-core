import asyncio
import logging
import subprocess

logger = logging.getLogger("ownline_core_log")


def execute_command(cmd, config_name='development'):
    if config_name == 'production':
        return execute_command_really_not_async(cmd)
    else:
        logger.info("NOT executing (dev) command: {}".format(" ".join(cmd)))
        return True, 'stderr', 'stdout'


def execute_command_really_async(cmd):
    loop = asyncio.get_running_loop()
    coro = asyncio.create_subprocess_exec(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, loop=loop)

    r = loop.run_until_complete(coro)
    logger.info(r)

    # stdout, stderr = await proc.communicate()
    #
    # print(f'[{cmd!r} exited with {proc.returncode}]')
    # if stdout:
    #     print(f'[stdout]\n{stdout.decode()}')
    # if stderr:
    #     print(f'[stderr]\n{stderr.decode()}')


def execute_command_really_not_async(cmd):
    logger.info("Executing command: {}".format(" ".join(cmd)))
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    logger.info("Execution result: code: {}, stderr: {}, stdout: {}".format(result.returncode,
                                                                                 result.stderr.decode(),
                                                                                 result.stdout.decode()))
    if result.returncode == 0:
        return True, result.stderr.decode(), result.stdout.decode()
    else:
        return False, result.stderr.decode(), result.stdout.decode()

