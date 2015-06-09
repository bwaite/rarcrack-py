#!/usr/bin/env python3
"""Rarcrack-py allows you to brute for the password protection on
archive files"""

import itertools
from multiprocessing import Queue, Process, cpu_count
import subprocess
import argparse
from collections import namedtuple
import atexit
import os
import json

DEV_NULL = open("/dev/null", "w")

TIMEOUT = 60

CrackResult = namedtuple('CrackResult', ['result', 'line',
                                         'password', 'exception'])

ArchiveInfo = namedtuple('ArchiveInfo', ['cmd', 'extension', 'success_str'])

UNRAR_CMD = ArchiveInfo("unrar t -y -p%s %s", '.rar', 'All OK')

UN7Z_CMD = ArchiveInfo("7za t -y -p%s %s", '.7z', 'Everything is Ok')

UNZIP_CMD = ArchiveInfo("unzip -P%s -t %s", '.zip', 'OK')


def close_devnull():
    """Closes the /dev/null device. Used with atexit so I don't
    have to remember to call it"""
    DEV_NULL.close()

atexit.register(close_devnull)


class CrackProducer(object):
    """"""

    def __init__(self, cmd: ArchiveInfo, tasks: Queue,
                 results: Queue, consumers, filename):
        self._cmd = cmd
        self._tasks = tasks
        self._results = results
        self._consumers = consumers
        self._filename = filename

    @property
    def cmd(self):
        return self._cmd

    @property
    def tasks(self):
        return self._tasks

    @property
    def results(self):
        return self._results

    @property
    def filename(self):
        return self._filename

    @staticmethod
    def _save_status(stat: dict, status_file):
        status_file.seek(0)
        json.dump(stat, status_file)

    def end_crack(self):
        # Tell consumers to stop
        for i in self._consumers:
            self._tasks.put(None)

        # Wait for all of the tasks to finish
        for c in self._consumers:
            c.join()

        # Check the final results in the queue
        while not self._results.empty():
            result = self._results.get()
            if result is not False:
                print('result {0}'.format(result.password))
                with open(self.status_file, 'w') as status_file:
                    self._save_status({'password': result.password},
                                      status_file)
                                       
                    


class PasswordBruteForcer(CrackProducer):
    """Generates passwords that can be used to brute force the archive"""

    default_chars = "0123456789" + \
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

    def __init__(self, cmd: ArchiveInfo, tasks: Queue, results: Queue,
                 consumers, filename: str, chars=default_chars, limit=8):
        super().__init__(cmd, tasks, results, consumers, filename)
        self.passgen = self.password_generator(chars, limit)

    @staticmethod
    def password_generator(iterable, limit):
        "Creates a generator using the chars provided in the constructor"
        s = list(iterable)
        return itertools.chain.from_iterable(
            itertools.product(s, repeat=r) for r in range(limit + 1))

    def run(self):
        """Start the password cracking"""
        stop = False

        print("Starting")
        for linenum, genpass in enumerate(self.passgen):
            if stop:
                break

            word = ''.join(genpass)

            self.tasks.put(Task(word, self.cmd, linenum, self.filename))

            if linenum % 1000 == 0:
                print("Count {0} Word {1}".format(linenum, word))

            while not self.results.empty():
                result = self.results.get()
                if result.result is not False:
                    print('result {0}'.format(result.password))
                    stop = True
                    break

        return


class FileProducer(CrackProducer):
    """Reads passwords from a file"""

    def __init__(self, cmd: ArchiveInfo, tasks: Queue, results: Queue,
                 consumers, filename: str, wordlist: str):
        super().__init__(cmd, tasks, results, consumers, filename)
        self.wordlist = wordlist
        self.status_file = filename + "_status.json"
        self.min_line_set = set()

    def run(self):
        """Start the password cracking"""
        stop = False

        start_line = 0

        if os.path.exists(self.status_file):
            with open(self.status_file, 'r') as status:
                s = json.load(status)
                if "password" in s and len(s["password"]) > 0:
                    print("Password is {0}".format(s["password"]))
                    return
                if "current_line" in s:
                    start_line = s["current_line"]

        if start_line > 0:
            print("Starting at line {0}".format(start_line))
        else:
            print("Starting")

        with open(self.wordlist, 'r', errors='ignore') as words, \
             open(self.status_file, 'w') as status_file:

            stat = {'current_line': 0, 'password': ''}
            self._save_status(stat, status_file)

            for linenum, word in enumerate(words):
                if stop:
                    break

                if linenum < start_line:
                    continue

                stat['current_line'] = linenum

                # Skip comments in the wordlist
                if word.startswith("#!comment:"):
                    continue

                self.min_line_set.add(linenum)
                self.tasks.put(Task(word, self.cmd, linenum, self.filename))

                if linenum % 1000 == 0:
                    stat['current_line'] = min(self.min_line_set)
                    self._save_status(stat, status_file)
                    print("Count {0} Word {1}".format(linenum, word))

                while not self.results.empty():
                    result = self.results.get()
                    self.min_line_set.remove(result.line)

                    if result.result is not False:

                        stat['password'] = result.password.strip()
                        stat['current_line'] = result.line
                        self._save_status(stat, status_file)
                        print('result {0}'.format(result.password))
                        stop = True
                        break

        return


class Consumer(Process):
    """Reads passwords from the queue and runs them in a new process"""

    def __init__(self, task_queue, result_queue):
        Process.__init__(self)
        self.task_queue = task_queue
        self.result_queue = result_queue

    def run(self):

        while True:
            next_task = self.task_queue.get()
            if next_task is None:
                #self.task_queue.task_done()
                break

            answer = next_task()
            #self.task_queue.task_done()

            if answer.result is not False:
                self.result_queue.put(answer)

        return


class Task(object):
    """Tests the password against the archive file"""

    def __init__(self, password: str, info: ArchiveInfo,
                 line: int, filename: str):
        self.password = password
        self.info = info
        self.line = line
        self.filename = filename

    def __call__(self) -> CrackResult:
        final_cmd = self.info.cmd % (self.password, self.filename)
        res = ""

        try:
            res = str(subprocess.check_output(final_cmd.split(),
                                              stderr=DEV_NULL,
                                              timeout=TIMEOUT))
        except subprocess.CalledProcessError as e:
            return CrackResult(result=False, line=self.line,
                               password=self.password, exception=e)

        except subprocess.TimeoutExpired as e:
            return CrackResult(result=False, line=self.line,
                               password=self.password, exception=e)

        if res.find(self.info.success_str) > -1:
            return CrackResult(result=True, line=self.line,
                               password=self.password, exception=None)

        return CrackResult(result=False, line=self.line,
                           password=self.password, exception=None)

    def __str__(self):
        return '{0} , {1}, {2}'.format(self.password, self.info, self.line)


def main():
    """Create the queues, start the processes, and crack"""
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", type=str, help="rar file to crack")
    parser.add_argument("--wordlist", type=str, help="wordlist to use")
    parser.add_argument("--procs", type=int, help="number of processes to use")
    args = parser.parse_args()

    num_consumers = cpu_count() * 2

    if args.procs:
        num_consumers = args.procs

    tasks = Queue(num_consumers * 10)
    results = Queue()

    consumers = [Consumer(tasks, results) for i in range(num_consumers)]

    for c in consumers:
        c.start()

    cmd = None

    (_, ext) = os.path.splitext(args.filename)

    if ext == UNRAR_CMD.extension:
        cmd = UNRAR_CMD
    elif ext == UNZIP_CMD.extension:
        cmd = UNZIP_CMD
    elif ext == UN7Z_CMD.extension:
        cmd = UN7Z_CMD
    else:
        print("Could not match extension")
        exit(-1)

    producer = None

    if args.wordlist is not None:
        producer = FileProducer(cmd, tasks, results, consumers,
                                args.filename, args.wordlist)
        producer.run()
    else:
        producer = PasswordBruteForcer(cmd, tasks, results, consumers,
                                       args.filename)
        producer.run()

    producer.end_crack()

    print("Finished")

if __name__ == '__main__':
    main()
