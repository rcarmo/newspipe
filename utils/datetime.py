def parseTime (text):
    AM = 1
    PM = 2
    UNKNOWN = 3

    text = text.lower()

    if 'am' in text:
        ampm = AM
        text = text.replace('am', '')
    elif 'pm' in text:
        ampm = PM
        text = text.replace('pm', '')
    else:
        ampm = UNKNOWN

    text = text.strip()
    slices = text.split(':')
    if len(slices) == 1:
        slices.append('0')

    try:
        hours = int(slices[0])
        minutes = int(slices[1])
    except ValueError:
        return None

    if ampm == PM:
        hours = hours + 12

    return (hours, minutes)

    return None

def parseTimeRange (text):
    begin, end = None, None

    text = text.strip()

    separators = [x for x in (' , ; to = / | -').split(' ') if x]
    separators.append(' ')

    slices = None
    for each in separators:
        aux = text.split(each)
        if len(aux) == 2:
            slices = aux

    if slices:
        slices = [x.strip() for x in slices]
        begin = parseTime(slices[0])
        end = parseTime(slices[1])
        if begin and end:
            return (begin, end)

    return None

def checkTime (range):
    n = datetime.now()
    hours = n.hour
    minutes = n.minute

    begin = range[0][0]*100 + range[0][1]
    end =   range[1][0]*100 + range[1][1]
    current = hours*100 + minutes

    if end < begin:
        end += 2400

    result = begin <= current <= end

    return result