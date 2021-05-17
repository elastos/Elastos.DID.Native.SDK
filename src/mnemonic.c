/*
 * Copyright (c) 2019 - 2021 Elastos Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "ela_did.h"
#include "HDkey.h"
#include "diderror.h"

const char *Mnemonic_Generate(const char *language)
{
    DIDERROR_INITIALIZE();

    return HDKey_GenerateMnemonic(language);

    DIDERROR_FINALIZE();
}

void Mnemonic_Free(void *mnemonic)
{
    DIDERROR_INITIALIZE();

    HDKey_FreeMnemonic(mnemonic);

    DIDERROR_FINALIZE();
}

bool Mnemonic_IsValid(const char *mnemonic, const char *language)
{
    DIDERROR_INITIALIZE();

    return HDKey_MnemonicIsValid(mnemonic, language);

    DIDERROR_FINALIZE();
}

const char *Mnemonic_GetLanguage(const char *mnemonic)
{
    int i;
    const char *languages[] = { "english", "french", "spanish", "japanese",
            "chinese_simplified", "chinese_traditional", "czech", "italian", "korean" };

    DIDERROR_INITIALIZE();

    CHECK_ARG(!mnemonic || !*mnemonic, "Invalid mnemonic string.", NULL);

    for (i = 0; i < 9; i++) {
        if (HDKey_MnemonicIsValid(mnemonic, languages[i]))
            return strdup(languages[i]);
    }

    return NULL;

    DIDERROR_FINALIZE();
}
