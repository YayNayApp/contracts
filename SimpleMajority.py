import smartpy as sp

## Types
#

TGetProofsRequestPayload = sp.TRecord(
    address=sp.TAddress, 
    callback_address=sp.TAddress, 
    callback_entrypoint=sp.TString
)
TGetProofsResponsePayload = sp.TRecord(
  address = sp.TAddress,
  proofs = sp.TMap(sp.TString, sp.TRecord(
    register_date = sp.TTimestamp, 
    verified = sp.TBool
  ))
)

## TezID
#

class TezID(sp.Contract):
  def __init__(self, admin, cost):
    self.init(
      admin = admin, 
      identities = {},
      cost = cost
    )

  @sp.entry_point
  def setAdmin(self, new_admin):
    sp.if sp.sender != self.data.admin:
        sp.failwith("Only admin can set admin")
    self.data.admin = new_admin

  @sp.entry_point
  def setCost(self, new_cost):
    sp.if sp.sender != self.data.admin:
        sp.failwith("Only admin can set cost")
    self.data.cost = new_cost

  @sp.entry_point
  def registerAddress(self):
    sp.if sp.amount < self.data.cost:
      sp.failwith("Amount too low")
    sp.if self.data.identities.contains(sp.sender):
      sp.failwith("Address already registered")
    self.data.identities[sp.sender] = {}

  @sp.entry_point
  def removeAddress(self):
    sp.if sp.amount < self.data.cost:
      sp.failwith("Amount too low")
    sp.if self.data.identities.contains(sp.sender):
      del self.data.identities[sp.sender]
    sp.else:
      sp.failwith("Address not registered")

  @sp.entry_point
  def registerProof(self, proof):
    sp.set_type(proof.type, sp.TString)
    sp.if sp.amount < self.data.cost:
      sp.failwith("Amount too low")
    self.data.identities[sp.sender][proof.type] = sp.record(
      register_date = sp.now,
      verified = False
    )

  @sp.entry_point
  def verifyProof(self, proofVer):
    sp.set_type(proofVer.type, sp.TString)
    sp.if sp.sender != self.data.admin:
      sp.failwith("Only admin can verify")
    identity = self.data.identities[proofVer.tzaddr]
    identity[proofVer.type].verified = True
    
  @sp.entry_point
  def send(self, receiverAddress, amount):
    sp.if sp.sender != self.data.admin:
      sp.failwith("Only admin can send")
    sp.send(receiverAddress, amount)
    
  @sp.entry_point
  def getProofs(self, address, callback_address, callback_entrypoint):
    sp.set_type(address, sp.TAddress)
    sp.set_type(callback_address, sp.TAddress)
    sp.set_type(callback_entrypoint, sp.TString)
    proofs = sp.local("proofs", {})
    sp.if self.data.identities.contains(address):
        pr = self.data.identities[address]
        proofs.value = pr
    c = sp.contract(TGetProofsResponsePayload, sp.sender, entry_point="register").open_some()
    sp.transfer(sp.record(address=address, proofs=proofs.value), sp.mutez(0), c)
    
## SimpleMajority
#
  
class SimpleMajority(sp.Contract):
    def __init__(self, ynid, admin, name, question, cost, start, end, requiredMajority, maxParticipants, tezid, requiredProofs):
      self.init(
        ynid = ynid,
        admin = admin,
        name = name,
        question = question,
        cost = cost,
        start = start,
        end = end,
        requiredMajority = requiredMajority,
        maxParticipants = maxParticipants,
        tezid = tezid,
        requiredProofs = requiredProofs,
        resolved = False,
        resolve = '',
        participants = {}
      )
      
    @sp.entry_point
    def register(self, ptr):
        sp.if sp.sender != self.data.tezid:
            sp.failwith('Only TezID can register')
        sp.set_type(ptr, TGetProofsResponsePayload)
        sp.set_type(ptr.address, sp.TAddress)
        validProofs = sp.local("validProofs", [])
        sp.for requiredProof in self.data.requiredProofs:
            sp.if ptr.proofs.contains(requiredProof):
                sp.if ptr.proofs[requiredProof].verified:
                    validProofs.value.push(requiredProof)
        sp.if sp.len(self.data.requiredProofs) == sp.len(validProofs.value):
            self.data.participants[ptr.address] = -1

    @sp.entry_point
    def signup(self):
        sp.if self.data.maxParticipants > 0:
            sp.if sp.len(self.data.participants) >= self.data.maxParticipants:
                sp.failwith('Maximum number of participants already registered')
        c = sp.contract(TGetProofsRequestPayload, self.data.tezid, entry_point="getProofs").open_some()
        sp.transfer(sp.record(address=sp.sender, callback_address=sp.self_address, callback_entrypoint="register"), sp.mutez(0), c)

    @sp.entry_point
    def vote(self, vote):
        sp.set_type(vote, sp.TInt)
        sp.if self.data.resolved:
            sp.failwith("Vote already resolved")
        sp.if sp.amount < self.data.cost:
            sp.failwith("Amount too low")
        sp.if sp.now < self.data.start:
            sp.failwith("Vote not yet started")
        sp.if sp.now > self.data.end:
            sp.failwith("Vote has ended")
        sp.if self.data.participants.contains(sp.sender):
            sp.if vote < 0:
                sp.failwith('Invalid vote')
            sp.if vote > 1:
                sp.failwith('Invalid vote')
            self.data.participants[sp.sender] = vote
            
    @sp.entry_point
    def resolve(self):
        sp.if self.data.resolved:
            sp.failwith("Vote already resolved")
        sp.if sp.now < self.data.end:
            sp.failwith("Vote has not yet ended")
        yays = sp.local("yays",0)
        nays = sp.local("nays",0)
        sp.for vote in self.data.participants.values():
            sp.if vote == 1:
                yays.value += 1
            sp.if vote == 0:
                nays.value += 1
        yayPercent = sp.local("yayPercent",0)
        yayPercent.value = ( 100 * yays.value + (yays.value + nays.value)/2 ) / (yays.value + nays.value)
        # Should give accuracy of +/- 0.5%
        # Got the percent calc function from here:
        # https://stackoverflow.com/questions/19551842/how-to-compute-percentage-using-fixed-point-arithmetic
        sp.if yayPercent.value >= self.data.requiredMajority:
            self.data.resolve = 'yay'
        sp.else:
            self.data.resolve = 'nay'
        self.data.resolved = True

    @sp.entry_point
    def send(self, receiverAddress, amount):
        sp.if sp.sender != self.data.admin:
            sp.failwith("Only admin can send")
        sp.send(receiverAddress, amount)

## Tests
#
        
@sp.add_test(name = "Call TezID from other contract")
def test():
  admin = sp.test_account("admin")
  user = sp.test_account("User")
  user2 = sp.test_account("User2")
  user3 = sp.test_account("User3")
  user4 = sp.test_account("User4")
  user5 = sp.test_account("User5")
  cost = sp.tez(5)
  emailProof = sp.record(
    type = 'email'
  )
  phoneProof = sp.record(
    type = 'phone'
  )
  verifyEmailProofUser1 = sp.record(
    tzaddr = user.address,
    type = 'email'
  )
  verifyPhoneProofUser1 = sp.record(
    tzaddr = user.address,
    type = 'phone'
  )
  verifyEmailProofUser2 = sp.record(
    tzaddr = user2.address,
    type = 'email'
  )
  verifyEmailProofUser4 = sp.record(
    tzaddr = user4.address,
    type = 'email'
  )
  verifyPhoneProofUser4 = sp.record(
    tzaddr = user4.address,
    type = 'phone'
  )
  verifyEmailProofUser5 = sp.record(
    tzaddr = user5.address,
    type = 'email'
  )
  verifyPhoneProofUser5 = sp.record(
    tzaddr = user5.address,
    type = 'phone'
  )
  start = sp.timestamp_from_utc(2021, 1, 1, 0, 0, 0)
  end = sp.timestamp_from_utc(2022, 1, 1, 0, 0, 0)

  scenario = sp.test_scenario()
  c1 = TezID(admin.address, cost)
  scenario += c1
  c2 = SimpleMajority(
      1,
      admin.address,
      "Off with their heads!?",
      "Shall we execute the bankers?",
      sp.tez(1),
      start,
      end,
      50,
      2,
      c1.address, 
      ["email","phone"])
  scenario += c2
  
  ## A user with the correct valid proofs can register as participant
  #
  scenario += c1.registerAddress().run(sender = user, amount = sp.tez(5))
  scenario += c1.registerProof(emailProof).run(sender = user, amount = sp.tez(5))
  scenario += c1.registerProof(phoneProof).run(sender = user, amount = sp.tez(5))
  scenario += c1.verifyProof(verifyEmailProofUser1).run(sender = admin)
  scenario += c1.verifyProof(verifyPhoneProofUser1).run(sender = admin)
  scenario += c2.signup().run(sender = user)
  scenario.verify(c2.data.participants.contains(user.address))

  ## A user without the correct valid proofs cannot register as participant
  #
  scenario += c1.registerAddress().run(sender = user2, amount = sp.tez(5))
  scenario += c1.registerProof(emailProof).run(sender = user2, amount = sp.tez(5))
  scenario += c1.registerProof(phoneProof).run(sender = user2, amount = sp.tez(5))
  scenario += c1.verifyProof(verifyEmailProofUser2).run(sender = admin)
  scenario += c2.signup().run(sender = user2)
  scenario.verify(c2.data.participants.contains(user2.address) == False)
  
  ## A user not registered on TezID cannot register as participant
  #
  scenario += c2.signup().run(sender = user3)
  scenario.verify(c2.data.participants.contains(user3.address) == False)
  
  ## Only TezID can call register endpoiint
  #
  emailProofCheat = sp.record(
      register_date = sp.timestamp(0),
      verified = True
  )
  phoneProofCheat = sp.record(
      register_date = sp.timestamp(0),
      verified = True
  )
  proofs = {}
  proofs['email'] = emailProofCheat
  proofs['phone'] = phoneProofCheat
  pr = sp.record(address = user3.address, proofs = proofs)
  scenario += c2.register(pr).run(sender = user3, valid=False)
  
  ## A registered user can vote
  #
  calltime = sp.timestamp_from_utc(2021, 4, 1, 0, 0, 0)
  scenario += c2.vote(1).run(sender = user, amount = sp.tez(1), now = calltime)
  scenario.verify(c2.data.participants[user.address] == 1)
  
  ## A registered user cannot vote if too low cost
  #
  calltime = sp.timestamp_from_utc(2021, 4, 1, 0, 0, 0)
  scenario += c2.vote(1).run(sender = user, amount = sp.tez(0), now = calltime, valid = False)

  ## A registered user cannot vote if too early
  #
  calltime = sp.timestamp_from_utc(2020, 4, 1, 0, 0, 0)
  scenario += c2.vote(1).run(sender = user, amount = sp.tez(1), now = calltime, valid = False)

  ## A registered user cannot vote if too late
  #
  calltime = sp.timestamp_from_utc(2023, 1, 1, 0, 0, 0)
  scenario += c2.vote(1).run(sender = user, amount = sp.tez(1), now = calltime, valid = False)
  
  ## A user with the correct valid proofs cannot register as participant if maxParticipants has been reached
  #
  scenario += c1.registerAddress().run(sender = user4, amount = sp.tez(5))
  scenario += c1.registerProof(emailProof).run(sender = user4, amount = sp.tez(5))
  scenario += c1.registerProof(phoneProof).run(sender = user4, amount = sp.tez(5))
  scenario += c1.verifyProof(verifyEmailProofUser4).run(sender = admin)
  scenario += c1.verifyProof(verifyPhoneProofUser4).run(sender = admin)
  scenario += c2.signup().run(sender = user4)
  calltime = sp.timestamp_from_utc(2021, 4, 1, 0, 0, 0)
  scenario += c2.vote(0).run(sender = user4, amount = sp.tez(1), now = calltime)
  scenario.verify(c2.data.participants.contains(user4.address))
  scenario += c1.registerAddress().run(sender = user5, amount = sp.tez(5))
  scenario += c1.registerProof(emailProof).run(sender = user5, amount = sp.tez(5))
  scenario += c1.registerProof(phoneProof).run(sender = user5, amount = sp.tez(5))
  scenario += c1.verifyProof(verifyEmailProofUser5).run(sender = admin)
  scenario += c1.verifyProof(verifyPhoneProofUser5).run(sender = admin)
  scenario += c2.signup().run(sender = user5, valid = False)
  
  ## You cannot call resolve too soon
  #
  calltime = sp.timestamp_from_utc(2021, 4, 1, 0, 0, 0)
  scenario += c2.resolve().run(sender = user3, now = calltime, valid = False)
  
  ## Anyone can call resolve after vote has ended
  #
  calltime = sp.timestamp_from_utc(2022, 1, 2, 0, 0, 0)
  scenario += c2.resolve().run(sender = user3, now = calltime)
  scenario.verify(c2.data.resolved)
  scenario.verify(c2.data.resolve == 'yay')
  
  
