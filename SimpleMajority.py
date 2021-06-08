import smartpy as sp

TezID = sp.io.import_stored_contract("TezID v2")
    
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
        signups = {},
        participants = {}
      )
      
    @sp.entry_point
    def register(self, address, proofs):
        sp.if sp.sender != self.data.tezid:
            sp.failwith('Only TezID can register')
        sp.set_type(address, sp.TAddress)
        sp.set_type(proofs, TezID.TProofs)
        sp.if self.data.signups.contains(address) == False:
            sp.failwith('Address has not signed up')
        validProofs = sp.local("validProofs", [])
        sp.for requiredProof in self.data.requiredProofs:
            sp.if proofs.contains(requiredProof):
                sp.if proofs[requiredProof].verified:
                    validProofs.value.push(requiredProof)
        sp.if sp.len(self.data.requiredProofs) == sp.len(validProofs.value):
            self.data.participants[address] = -1
        del self.data.signups[address]

    @sp.entry_point
    def signup(self):
        self.data.signups[sp.sender] = True
        sp.if self.data.maxParticipants > 0:
            sp.if sp.len(self.data.participants) >= self.data.maxParticipants:
                sp.failwith('Maximum number of participants already registered')
        callback_address = sp.self_entry_point_address(entry_point = 'register')
        c = sp.contract(TezID.TGetProofsRequestPayload, self.data.tezid, entry_point="getProofs").open_some()
        sp.transfer(sp.record(address=sp.sender, callback_address=callback_address), sp.mutez(0), c)

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
        
@sp.add_test(name = "Call TezID from other contract", is_default=True)
def test():
  admin = sp.test_account("admin")
  user = sp.test_account("User")
  user2 = sp.test_account("User2")
  user3 = sp.test_account("User3")
  user4 = sp.test_account("User4")
  user5 = sp.test_account("User5")

  start = sp.timestamp_from_utc(2021, 1, 1, 0, 0, 0)
  end = sp.timestamp_from_utc(2022, 1, 1, 0, 0, 0)

  scenario = sp.test_scenario()
  store, ctrl = TezID.initTests(admin, scenario)
  yn = SimpleMajority(
      1,
      admin.address,
      "Off with their heads!?",
      "Shall we execute the bankers?",
      sp.tez(1),
      start,
      end,
      50,
      2,
      store.address, 
      ["email","phone"])
  scenario += yn
  
  ## A user with the correct valid proofs can register as participant
  #
  scenario += ctrl.registerProof('email').run(sender = user, amount = sp.tez(5))
  scenario += ctrl.registerProof('phone').run(sender = user, amount = sp.tez(5))
  scenario += ctrl.verifyProof(sp.record(address=user.address, prooftype='email')).run(sender = admin)
  scenario += ctrl.verifyProof(sp.record(address=user.address, prooftype='phone')).run(sender = admin)
  scenario += yn.signup().run(sender = user)
  scenario.verify(yn.data.participants.contains(user.address))

  ## A user without the correct valid proofs cannot register as participant
  #
  scenario += ctrl.registerProof('email').run(sender = user2, amount = sp.tez(5))
  scenario += ctrl.registerProof('phone').run(sender = user2, amount = sp.tez(5))
  scenario += ctrl.verifyProof(sp.record(address=user2.address, prooftype='email')).run(sender = admin)
  scenario += yn.signup().run(sender = user2)
  scenario.verify(yn.data.participants.contains(user2.address) == False)
  
  ## A user not registered on TezID cannot register as participant
  #
  scenario += yn.signup().run(sender = user3, valid=False)

  ## Only TezID can call register endpoiint
  #
  emailProofCheat = sp.record(
      register_date = sp.timestamp(0),
      verified = True,
      meta = {}
  )
  phoneProofCheat = sp.record(
      register_date = sp.timestamp(0),
      verified = True,
      meta = {}
  )
  proofs = {}
  proofs['email'] = emailProofCheat
  proofs['phone'] = phoneProofCheat
  pr = sp.record(address = user3.address, proofs = proofs)
  scenario += yn.register(pr).run(sender = user3, valid=False)
  
  ## A registered user can vote
  #
  calltime = sp.timestamp_from_utc(2021, 4, 1, 0, 0, 0)
  scenario += yn.vote(1).run(sender = user, amount = sp.tez(1), now = calltime)
  scenario.verify(yn.data.participants[user.address] == 1)
  
  ## A registered user cannot vote if too low cost
  #
  calltime = sp.timestamp_from_utc(2021, 4, 1, 0, 0, 0)
  scenario += yn.vote(1).run(sender = user, amount = sp.tez(0), now = calltime, valid = False)

  ## A registered user cannot vote if too early
  #
  calltime = sp.timestamp_from_utc(2020, 4, 1, 0, 0, 0)
  scenario += yn.vote(1).run(sender = user, amount = sp.tez(1), now = calltime, valid = False)

  ## A registered user cannot vote if too late
  #
  calltime = sp.timestamp_from_utc(2023, 1, 1, 0, 0, 0)
  scenario += yn.vote(1).run(sender = user, amount = sp.tez(1), now = calltime, valid = False)
  
  ## A user with the correct valid proofs cannot register as participant if maxParticipants has been reached
  #
  scenario += ctrl.registerProof('email').run(sender = user4, amount = sp.tez(5))
  scenario += ctrl.registerProof('phone').run(sender = user4, amount = sp.tez(5))
  scenario += ctrl.verifyProof(sp.record(address=user4.address, prooftype='email')).run(sender = admin)
  scenario += ctrl.verifyProof(sp.record(address=user4.address, prooftype='phone')).run(sender = admin)
  scenario += yn.signup().run(sender = user4)
  calltime = sp.timestamp_from_utc(2021, 4, 1, 0, 0, 0)
  scenario += yn.vote(0).run(sender = user4, amount = sp.tez(1), now = calltime)
  scenario.verify(yn.data.participants.contains(user4.address))
  scenario += ctrl.registerProof('email').run(sender = user5, amount = sp.tez(5))
  scenario += ctrl.registerProof('phone').run(sender = user5, amount = sp.tez(5))
  scenario += ctrl.verifyProof(sp.record(address=user4.address, prooftype='email')).run(sender = admin)
  scenario += ctrl.verifyProof(sp.record(address=user4.address, prooftype='phone')).run(sender = admin)
  scenario += yn.signup().run(sender = user5, valid = False)
  
  ## You cannot call resolve too soon
  #
  calltime = sp.timestamp_from_utc(2021, 4, 1, 0, 0, 0)
  scenario += yn.resolve().run(sender = user3, now = calltime, valid = False)
  
  ## Anyone can call resolve after vote has ended
  #
  calltime = sp.timestamp_from_utc(2022, 1, 2, 0, 0, 0)
  scenario += yn.resolve().run(sender = user3, now = calltime)
  scenario.verify(yn.data.resolved)
  scenario.verify(yn.data.resolve == 'yay')
