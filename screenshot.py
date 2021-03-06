from pyvirtualdisplay import Display
from selenium import webdriver
from datetime import datetime
from threading import Lock
import os
import logging

logging.getLogger(__name__)

lock = Lock()


def screenshot(iptuple, port, dir):
    """This method is responsible for making and saving screenshots with an hidden virtual desktop(not avaiable
    on windows)"""
    lock.acquire()
    try:
        display = Display(visible=0, size=(1980, 1024))
        display.start()
        driver = webdriver.Chrome(chrome_options=get_selenium_options())
        driver.set_page_load_timeout(6)
        id, ip = iptuple
        if port == 80:
            driver.get('http://' + str(ip))
            ipcorrect = str(ip)
            ipcorrect = ipcorrect.replace(".", "_")
            if not os.path.exists(dir):
                os.mkdir(dir)
            driver.save_screenshot(os.path.join(dir, datetime.now().strftime("%d-%m-%Y_%H^%M^%S") +
                                                "__{0}_{1}_screenshot.png".format(ipcorrect, str(port))))
            logging.info("Screenshot Taken from : {0} port: {1}".format(ipcorrect, str(port)))
        elif port == 443:
            driver.get('https://' + str(ip))
            ipcorrect = str(ip)
            ipcorrect = ipcorrect.replace(".", "_")
            if not os.path.exists(dir):
                os.mkdir(dir)
            driver.save_screenshot(os.path.join(dir, datetime.now().strftime("%d-%m-%Y_%H^%M^%S") +
                                                "__({0})_{1}_screenshot.png".format(ipcorrect, str(port))))
            logging.info("Screenshot Taken from : {0} port: {1}".format(ipcorrect, str(port)))
        driver.close()
        display.stop()
    except Exception as e:
        print(e)
        pass
    lock.release()


def get_selenium_options():
    """Options needed by selenium for working"""
    options = webdriver.ChromeOptions()
    options.add_argument('--ignore-certificate-errors')
    options.add_argument("--test-type")
    options.add_argument("--start-maximized")
    options.add_argument("--no-sandbox")
    return options
