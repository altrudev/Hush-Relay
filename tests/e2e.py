# Hush Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev) and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Multi-browser end-to-end test: invite by QR picture, live chat, recovery words,
moving an account by QR, recovering on another device. Run via tests/run.sh --e2e."""
import os, sys, tempfile, time
from playwright.sync_api import sync_playwright
U=os.environ.get('BASE','http://localhost:8099/index.html'); S=tempfile.mkdtemp()+'/'
CHROME=os.environ.get('CHROME')
errs=[]; dialogs=[]
def page(b,tag):
    p=b.new_context(bypass_csp=True).new_page()  # the app's CSP forbids eval; the test harness needs it
    p.on('pageerror',lambda e:errs.append(tag+': '+str(e)))
    p.on('console',lambda m: m.type=='error' and errs.append(tag+' console: '+m.text))
    p.on('dialog',lambda d:(dialogs.append(tag+': '+d.message),d.accept()))
    p.goto(U); return p
def create(p,name):
    p.fill('#nameIn',name); p.click('#createBtn'); p.wait_for_selector('#vList:not([hidden])')
def chat_with(p,name):
    if p.is_visible('#back'): p.click('#back')
    p.click(f'.contact:has-text("{name}")')
with sync_playwright() as pw:
    b=pw.chromium.launch(executable_path=CHROME) if CHROME else pw.chromium.launch()
    A=page(b,'A'); B=page(b,'B'); create(A,'Alice'); create(B,'Bob')
    # invite by QR picture
    A.click('#settingsBtn'); A.wait_for_function("document.querySelector('#inviteQR').naturalWidth>0")
    A.locator('#inviteQR').screenshot(path=S+'invite.png')
    B.set_input_files('#scanFile',S+'invite.png'); B.wait_for_selector('#vChat:not([hidden])')
    print('1 invite via QR picture: OK, chatting with', B.text_content('#title'))
    # live delivery
    A.click('#back'); time.sleep(1)
    B.fill('#txt','hello alice'); t=time.time(); B.click('#composer button')
    A.wait_for_selector('.contact:has-text("Bob") .badge',timeout=10000); print('2 live delivery: %.1fs'%(time.time()-t))
    chat_with(A,'Bob'); A.fill('#txt','hi bob'); t=time.time(); A.click('#composer button')
    B.wait_for_selector('text=hi bob',timeout=10000); print('  reply live: %.1fs'%(time.time()-t))
    # recovery words
    A.click('#back'); A.click('#settingsBtn'); A.click('#recStart'); words=A.text_content('#recWords')
    A.fill('#recConfirm',words); A.click('#recSave'); A.wait_for_selector('#recOn:not([hidden])',timeout=15000)
    print('3 recovery words on:', words)
    # move account to C by QR picture
    C=page(b,'C'); C.click('#pairBtn'); C.wait_for_function("document.querySelector('#pairQR').naturalWidth>0")
    C.locator('#pairQR').screenshot(path=S+'pair.png'); ccode=C.text_content('#pairCode')
    A.click('#back'); A.set_input_files('#scanFile',S+'pair.png'); A.wait_for_selector('#vLink:not([hidden])')
    acode=A.text_content('#linkCode'); print('4 link codes match:', ccode==acode, ccode)
    A.click('#linkApprove')
    C.wait_for_selector('#vList:not([hidden])',timeout=30000); C.wait_for_selector('.contact:has-text("Bob")')
    A.wait_for_selector('#vSetup:not([hidden])',timeout=30000)
    print('  C signed in with contacts; A signed out:', A.is_visible('#vSetup'))
    chat_with(C,'Bob'); C.fill('#txt','from my new phone'); C.click('#composer button')
    B.wait_for_selector('text=from my new phone',timeout=15000)
    print('  B sees new-device notice:', B.locator('.m.sys').count()>0)
    B.fill('#txt','got it'); B.click('#composer button'); C.wait_for_selector('text=got it',timeout=15000); print('  C <-> B both ways after move: OK')
    # recover on D with words
    D=page(b,'D'); D.fill('#recoverWords',words); D.click('#recoverBtn')
    D.wait_for_selector('.contact:has-text("Bob")',timeout=30000); print('5 recovered on D with words: OK')
    chat_with(D,'Bob'); D.fill('#txt','recovered'); D.click('#composer button'); B.wait_for_selector('text=recovered',timeout=15000); print('  D -> B: OK')
    b.close()
real=[e for e in errs if '400 (Bad Request)' not in e]  # 400s are the deliberate relay probe at sign-up
print('  dialogs:', dialogs); print('  errors:', real or 'none')
sys.exit(1 if real else 0)
